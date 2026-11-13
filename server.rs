//===================================================================================//
// rawrpc::server — RawTranslator, objetos por apertura y demuxer                    //
//===================================================================================//
//
// Modelo de puertos (el de trivfs, sin libports):
//
//   control   lo recibe el padre en fsys_startup; sólo atiende fsys_getroot/goaway.
//   peropen   uno por cada fsys_getroot que tiene éxito; guarda el modo de apertura
//             y las credenciales, y es el puerto al que el cliente envía los servicios.
//             Se destruye cuando el kernel avisa de que ya no quedan send rights
//             (notificación no-senders).
//
// Todos están en un port set, que es donde escucha el bucle de servicio.

use std::collections::HashMap;

use hurd_rs::gnumach::mig::{MIG_TYPE_ERROR, MIG_BAD_ID, MIG_BAD_ARGUMENTS, MIG_NO_REPLY};
use hurd_rs::gnumach::kern_return::{kern_return_t, KERN_SUCCESS};
use hurd_rs::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use hurd_rs::gnumach::boolean::{boolean_t, MACH_BOOLEAN_TRUE, MACH_BOOLEAN_FALSE};
use hurd_rs::gnumach::message::*;
use hurd_rs::gnumach::error::{EROFS, EACCES};
use hurd_rs::gnumach::notify::MACH_NOTIFY_NO_SENDERS;
use hurd_rs::gnuhurd::fcntl::{O_READ, O_WRITE, O_EXEC};
use hurd_rs::gnuhurd::types::FS_RETRY_NORMAL;

use super::client::{CallError, RawClient};
use super::fsys::{self, Getroot, GetrootRequest, StringT, RetryPort};
use super::sys::{
    self, ports, Header, MsgId, ERR_REPLY_SIZE,
    HEADER_SIZE, 
};
use super::wire::{kinds_text, Kind, Port, Reader, Wire, WireError, WireTuple, Writer, FixedStr};
use super::{DESCRIBE_ID, REPLY_ID_OFFSET};

//-----------------------------------------------------------------------------------//
// Apertura                                                                          //
//-----------------------------------------------------------------------------------//

/// Estado de una apertura del nodo (equivale a trivfs_peropen + trivfs_protid).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peropen {
    /// Puerto por el que llegan las peticiones de esta apertura.
    pub port: mach_port_t,
    /// Subconjunto de O_READ | O_WRITE | O_EXEC concedido al abrir.
    pub openmodes: i32,
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

impl Peropen {
    /// Apertura sin modos ni credenciales: la que reciben los servicios cuando el
    /// mensaje no llega por un puerto creado por fsys_getroot (modo puente con trivfs
    /// o pruebas). Deniega todo lo que dependa de los modos.
    pub fn anonymous(port: mach_port_t) -> Self {
        Peropen { port, openmodes: 0, uids: Vec::new(), gids: Vec::new() }
    }
    pub fn can_read(&self) -> bool {
        self.openmodes & O_READ != 0
    }
    pub fn can_write(&self) -> bool {
        self.openmodes & O_WRITE != 0
    }
    pub fn is_privileged(&self) -> bool {
        self.uids.contains(&0)
    }
}

//-----------------------------------------------------------------------------------//
// Trait del translator                                                              //
//-----------------------------------------------------------------------------------//

/// Un translator declara su id base y la lista ordenada de servicios: el servicio
/// i-ésimo atiende el mensaje BASE_ID + i (los huecos se declaran con `skip`).
pub trait RawTranslator: Sized + Send + 'static {
    const BASE_ID: MsgId;

    /// Modos de apertura que admite el nodo (trivfs_allow_open).
    const ALLOW_OPEN: i32 = O_READ | O_WRITE | O_EXEC;

    fn services() -> Services<Self>;

    /// Comprobación adicional al abrir (trivfs_check_open_hook), después de la de
    /// permisos sobre el nodo subyacente. `po.port` aún no está asignado.
    fn open_root(&mut self, _po: &Peropen) -> Result<(), kern_return_t> {
        Ok(())
    }

    /// fsys_goaway (settrans -g). Ok: el bucle termina tras responder.
    fn goaway(&mut self, _flags: i32) -> Result<(), kern_return_t> {
        Ok(())
    }

    /// Se llama al activar fsys (tras fsys_startup) con el nodo subyacente.
    fn on_startup(&mut self, _realnode: Option<mach_port_t>) {}

    /// fsys_getroot (trivfs_getroot_hook). Por defecto, Getroot::Open: abrir como
    /// trivfs. Un Err se devuelve al padre tal cual y no toca dotdot.
    fn getroot(&mut self, _req: &GetrootRequest) -> Result<Getroot, kern_return_t> {
        Ok(Getroot::Open)
    }

    /// fsys_syncfs. Por defecto no hay nada que sincronizar (como trivfs).
    fn syncfs(&mut self, _wait: i32, _do_children: i32) -> Result<(), kern_return_t> {
        Ok(())
    }
}

//-----------------------------------------------------------------------------------//
// Handler: convierte una función tipada en un servicio                              //
//-----------------------------------------------------------------------------------//
//
// Se implementa para cualquier
//     Fn(&mut T, &Peropen, A1, ..., An) -> Result<R, kern_return_t>
// con Ai: Wire (n ≤ 4) y R: WireTuple ((), un valor o una tupla de hasta 4).
//
// Contrato de derechos (el de MIG): si un servicio recibe un Port y devuelve Err, NO
// debe haber liberado el derecho; el bucle destruye el mensaje entero. Si devuelve
// Ok, el derecho es suyo. No devolver nunca Err(KERN_SUCCESS).

pub enum Fail {
    Decode(WireError),
    Code(kern_return_t),
    Encode(WireError),
}

pub trait Handler<T, Args>: Send + Sync + 'static {
    fn arg_kinds() -> Vec<Kind>;
    fn ret_kinds() -> Vec<Kind>;
    fn invoke(&self, t: &mut T, po: &Peropen, r: &mut Reader<'_>, w: &mut Writer<'_>) -> Result<(), Fail>;
}

macro_rules! impl_handler {
    ($($A:ident $a:ident),*) => {
        impl<T, F, R, $($A,)*> Handler<T, ($($A,)*)> for F
        where
            F: Fn(&mut T, &Peropen $(, $A)*) -> Result<R, kern_return_t> + Send + Sync + 'static,
            R: WireTuple,
            $($A: Wire,)*
        {
            fn arg_kinds() -> Vec<Kind> {
                vec![$($A::KIND),*]
            }

            fn ret_kinds() -> Vec<Kind> {
                R::kinds()
            }

            fn invoke(&self, t: &mut T, po: &Peropen, r: &mut Reader<'_>, w: &mut Writer<'_>)
                -> Result<(), Fail>
            {
                $(let $a = $A::decode(r).map_err(Fail::Decode)?;)*
                r.finish().map_err(Fail::Decode)?;
                let out = (self)(t, po $(, $a)*).map_err(Fail::Code)?;
                out.encode_all(w).map_err(Fail::Encode)
            }
        }
    };
}

impl_handler!();
impl_handler!(A a);
impl_handler!(A a, B b);
impl_handler!(A a, B b, C c);
impl_handler!(A a, B b, C c, D d);

//-----------------------------------------------------------------------------------//
// Tabla de servicios                                                                //
//-----------------------------------------------------------------------------------//

type Erased<T> =
    Box<dyn Fn(&mut T, &Peropen, &mut Reader<'_>, &mut Writer<'_>) -> Result<(), Fail> + Send + Sync>;

pub struct Service<T> {
    pub name: &'static str,
    pub args: Vec<Kind>,
    pub rets: Vec<Kind>,
    call: Erased<T>,
}

pub struct Services<T> {
    /// None = id saltado (`skip` en la .defs).
    list: Vec<Option<Service<T>>>,
}

impl<T: 'static> Default for Services<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> Services<T> {
    pub fn new() -> Self {
        Services { list: Vec::new() }
    }

    /// Añade el siguiente servicio (id = BASE_ID + posición).
    pub fn add<Args, H: Handler<T, Args>>(mut self, name: &'static str, h: H) -> Self {
        assert!(
            !name.is_empty() && name != "-" && !name.contains([':', '\n', ',']),
            "nombre de servicio no válido: {name:?}"
        );
        assert!(self.iter().all(|s| s.name != name), "servicio duplicado: {name}");
        self.list.push(Some(Service {
            name,
            args: H::arg_kinds(),
            rets: H::ret_kinds(),
            call: Box::new(move |t: &mut T, po: &Peropen, r: &mut Reader<'_>, w: &mut Writer<'_>| {
                h.invoke(t, po, r, w)
            }),
        }));
        self
    }

    /// Deja `n` ids sin servicio (como `skip;` en una .defs): responden MIG_BAD_ID.
    pub fn skip(mut self, n: usize) -> Self {
        self.list.extend((0..n).map(|_| None));
        self
    }

    /// Número de ids que ocupa el subsistema (servicios + huecos).
    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Service<T>> {
        self.list.iter().flatten()
    }

    fn get(&self, i: usize) -> Option<&Service<T>> {
        self.list.get(i).and_then(|s| s.as_ref())
    }
}

//-----------------------------------------------------------------------------------//
// Servidor                                                                          //
//-----------------------------------------------------------------------------------//

enum Route {
    Describe,
    Service(usize),
    FsysGoaway,
    FsysGetroot,
    FsysSyncfs,
    NoSenders,
}

#[derive(Clone, Copy, Debug)]
struct FsysCfg {
    set: mach_port_t,
    control: mach_port_t,
    /// Nodo subyacente (realnode de fsys_startup), para comprobar permisos.
    realnode: Option<mach_port_t>,
}

pub struct RawServer<T: RawTranslator> {
    state: T,
    services: Services<T>,
    describe_text: String,
    fsys: Option<FsysCfg>,
    objects: HashMap<mach_port_t, Peropen>,
    /// Puerto creado en la petición en curso: si la respuesta no llega al cliente,
    /// nunca habrá MAKE_SEND ni notificación no-senders y hay que destruirlo a mano.
    created: Option<mach_port_t>,
    realnode: Option<Port>,
    exit_requested: bool,
}

impl<T: RawTranslator> RawServer<T> {
    pub fn new(state: T) -> Self {
        let services = T::services();
        let n = services.len() as MsgId;
        assert!(n < REPLY_ID_OFFSET, "como mmaximo 99 ids (las respuestas usan id + 100)");
        let range = T::BASE_ID..T::BASE_ID + n;
        assert!(
            !range.contains(&DESCRIBE_ID) && !range.contains(&MACH_NOTIFY_NO_SENDERS),
            "el rango de ids [{}, {}) contiene DESCRIBE_ID o una notificación de Mach",
            range.start,
            range.end
        );
        let describe_text = services
            .list
            .iter()
            .map(|s| match s {
                Some(s) => format!("{}:{}:{}", s.name, kinds_text(&s.args), kinds_text(&s.rets)),
                None => "-::".to_string(),
            })
            .collect::<Vec<_>>()
            .join("\n");
        RawServer {
            state,
            services,
            describe_text,
            fsys: None,
            objects: HashMap::new(),
            created: None,
            realnode: None,
            exit_requested: false,
        }
    }

    pub fn state(&self) -> &T {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut T {
        &mut self.state
    }

    pub fn base_id(&self) -> MsgId {
        T::BASE_ID
    }

    /// Ids que ocupa el subsistema (servicios + huecos).
    pub fn id_count(&self) -> usize {
        self.services.len()
    }

    /// Una línea "nombre:args:resultados" por id ("-::" en los huecos).
    pub fn describe_text(&self) -> &str {
        &self.describe_text
    }

    /// Modo sin trivfs. `set`: port set donde se reciben los mensajes (los puertos de
    /// cada apertura se añaden a él). `control`: sólo fsys. `realnode`: nodo sobre el
    /// que está instalado el translator; sin él, sólo pueden abrir usuarios con uid 0.
    pub fn enable_fsys(&mut self, set: mach_port_t, control: mach_port_t, realnode: Option<mach_port_t>) {
        let range = T::BASE_ID..T::BASE_ID + self.services.len() as MsgId;
        let fsys = fsys::FSYS_SUBSYSTEM..fsys::FSYS_SUBSYSTEM + REPLY_ID_OFFSET;
        assert!(
            range.end <= fsys.start || range.start >= fsys.end,
            "el rango de ids del translator se solapa con el subsistema fsys"
        );
        self.fsys = Some(FsysCfg { set, control, realnode });
        self.state.on_startup(realnode);
    }

    /// Nodo sobre el que está instalado el translator (resultado de fsys_startup).
    pub fn realnode(&self) -> Option<Port> {
        self.realnode
    }

    /// Aperturas vivas.
    pub fn open_count(&self) -> usize {
        self.objects.len()
    }

    pub fn peropen(&self, port: mach_port_t) -> Option<&Peropen> {
        self.objects.get(&port)
    }

    /// Se ha atendido un fsys_goaway con éxito.
    pub fn exit_requested(&self) -> bool {
        self.exit_requested
    }

    /// La respuesta a la petición anterior no se pudo entregar: si creó un puerto de
    /// apertura, se destruye (el cliente nunca lo recibió).
    pub fn reply_undelivered(&mut self) {
        if let Some(p) = self.created.take() {
            self.objects.remove(&p);
            ports::destroy_receive(p);
        }
    }

    /// Demuxer sobre buffers. `inp` empieza en la cabecera; `out` recibe la respuesta
    /// completa. Devuelve false si el mensaje no es para este servidor (y deja en `out`
    /// una respuesta MIG_BAD_ID, como el demuxer de MIG).
    pub fn demux(&mut self, inp: &[u8], out: &mut [u8]) -> bool {
        self.created = None;
        let Some(h) = sys::read_header(inp) else { return false };
        if out.len() < ERR_REPLY_SIZE {
            return false;
        }

        let mut rh = Header {
            bits: sys::reply_bits(h.bits),
            size: ERR_REPLY_SIZE as u32,
            remote: h.remote,
            local: MACH_PORT_NULL,
            seqno: 0,
            id: h.id.wrapping_add(REPLY_ID_OFFSET),
        };

        let Some(route) = self.route(h.id, h.local) else {
            write_reply(out, &rh, MIG_BAD_ID);
            return false;
        };

        match self.dispatch(route, &h, inp, out) {
            Ok((size, complex)) => {
                rh.size = size as u32;
                if complex {
                    rh.bits |= MACH_MSGH_BITS_COMPLEX;
                }
                write_reply(out, &rh, KERN_SUCCESS);
            }
            Err(code) => write_reply(out, &rh, code),
        }
        true
    }

    fn route(&self, id: MsgId, local: mach_port_t) -> Option<Route> {
        if let Some(cfg) = self.fsys {
            if local == cfg.control {
                return match id {
                    fsys::FSYS_GOAWAY => Some(Route::FsysGoaway),
                    fsys::FSYS_GETROOT => Some(Route::FsysGetroot),
                    fsys::FSYS_SYNCFS => Some(Route::FsysSyncfs),
                    _ => None,
                };
            }
            // Con fsys activo, los servicios sólo entran por puertos de apertura.
            if !self.objects.contains_key(&local) {
                return None;
            }
        }
        if id == MACH_NOTIFY_NO_SENDERS && self.objects.contains_key(&local) {
            return Some(Route::NoSenders);
        }
        if id == DESCRIBE_ID {
            return Some(Route::Describe);
        }
        let i = id.wrapping_sub(T::BASE_ID);
        (i >= 0 && self.services.get(i as usize).is_some()).then_some(Route::Service(i as usize))
    }

    fn dispatch(&mut self, route: Route, h: &Header, inp: &[u8], out: &mut [u8])
        -> Result<(usize, bool), kern_return_t>
    {
        let in_size = h.size as usize;
        if in_size < HEADER_SIZE || in_size > inp.len() {
            return Err(MIG_BAD_ARGUMENTS);
        }

        let mut r = Reader::new(&inp[..in_size], HEADER_SIZE, h.is_complex());
        let mut w = Writer::new(out, ERR_REPLY_SIZE);

        let res = match route {
            Route::Describe => r.finish().map_err(Fail::Decode).and_then(|_| {
                (T::BASE_ID, self.services.len() as u32, self.describe_text.clone())
                    .encode_all(&mut w)
                    .map_err(Fail::Encode)
            }),
            Route::Service(i) => {
                let anon;
                let po = match self.objects.get(&h.local) {
                    Some(po) => po,
                    None => {
                        anon = Peropen::anonymous(h.local);
                        &anon
                    }
                };
                let s = self.services.get(i).expect("ruta validada");
                (s.call)(&mut self.state, po, &mut r, &mut w)
            }
            Route::FsysGoaway => self.fsys_goaway(&mut r),
            Route::FsysGetroot => self.fsys_getroot(&mut r, &mut w),
            Route::FsysSyncfs => <(i32, i32)>::decode_all(&mut r)
                .and_then(|v| r.finish().map(|_| v))
                .map_err(Fail::Decode)
                .and_then(|(wait, children)| self.state.syncfs(wait, children).map_err(Fail::Code)),
            Route::NoSenders => {
                // mach_no_senders_notification_t: INTEGER_32 not_count. No se responde.
                let _mscount = u32::decode(&mut r).map_err(Fail::Decode);
                if self.objects.remove(&h.local).is_some() {
                    ports::destroy_receive(h.local);
                }
                Err(Fail::Code(MIG_NO_REPLY))
            }
        };

        let res = match res {
            Ok(()) => w.finish().map_err(|e| e.server_code()),
            Err(Fail::Decode(e)) | Err(Fail::Encode(e)) => Err(e.server_code()),
            Err(Fail::Code(c)) => Err(c),
        };
        if res.is_err() {
            // Una apertura creada en esta petición no llegará al cliente.
            self.reply_undelivered();
        }
        // Igual que el stub de MIG: la memoria fuera de línea recibida se libera sólo
        // si la RPC ha ido bien; si no, la libera mach_msg_destroy con el mensaje.
        if res.is_ok() {
            for (addr, len) in r.take_ool_regions() {
                sys::ool_deallocate(addr, len);
            }
        }
        res
    }

    fn fsys_goaway(&mut self, r: &mut Reader<'_>) -> Result<(), Fail> {
        let flags = i32::decode(r).map_err(Fail::Decode)?;
        r.finish().map_err(Fail::Decode)?;
        self.state.goaway(flags).map_err(Fail::Code)?;
        self.exit_requested = true;
        Ok(())
    }

    /// trivfs_S_fsys_getroot: comprueba modos y permisos, crea el puerto de la
    /// apertura y lo devuelve con MAKE_SEND.
    fn fsys_getroot(&mut self, r: &mut Reader<'_>, w: &mut Writer<'_>) -> Result<(), Fail> {
        let req = GetrootRequest {
            dotdot: Port::decode(r).map_err(Fail::Decode)?,
            uids: Vec::<u32>::decode(r).map_err(Fail::Decode)?,
            gids: Vec::<u32>::decode(r).map_err(Fail::Decode)?,
            flags: i32::decode(r).map_err(Fail::Decode)?,
        };
        r.finish().map_err(Fail::Decode)?;
        let cfg = self.fsys.expect("ruta sólo con fsys activo");

        // Errores: no tocamos dotdot (lo destruye el bucle con el mensaje).
        match self.state.getroot(&req).map_err(Fail::Code)? {
            Getroot::Open => {}
            Getroot::Retry { retry, name, port } => {
                let reply_port = match port {
                    RetryPort::Null => Port::null(),
                    RetryPort::Dotdot => Port::move_send(req.dotdot.name),
                    RetryPort::Send(p) => p,
                };
                (retry, FixedStr::<1024>(name), reply_port).encode_all(w).map_err(Fail::Encode)?;
                if port != RetryPort::Dotdot {
                    sys::port_deallocate(req.dotdot.name);
                }
                return Ok(());
            }
        }

        let rwx = O_READ | O_WRITE | O_EXEC;
        let wanted = req.flags & rwx;
        if wanted & O_WRITE & !T::ALLOW_OPEN != 0 {
            return Err(Fail::Code(EROFS));
        }
        if wanted & !T::ALLOW_OPEN != 0 {
            return Err(Fail::Code(EACCES));
        }

        let po = Peropen { port: MACH_PORT_NULL, openmodes: wanted, uids: req.uids, gids: req.gids };
        if !po.is_privileged() {
            let Some(realnode) = cfg.realnode else { return Err(Fail::Code(EACCES)) };
            let perms = check_access(realnode, &po.uids, &po.gids).map_err(Fail::Code)?;
            if wanted & !perms != 0 {
                return Err(Fail::Code(EACCES));
            }
        }
        self.state.open_root(&po).map_err(Fail::Code)?;

        let port = ports::allocate_receive().map_err(Fail::Code)?;
        let setup = ports::move_member(port, cfg.set).and_then(|_| ports::request_no_senders(port));
        if let Err(kr) = setup {
            ports::destroy_receive(port);
            return Err(Fail::Code(kr));
        }
        self.objects.insert(port, Peropen { port, ..po });
        self.created = Some(port);

        (FS_RETRY_NORMAL, StringT::default(), Port::make_send(port))
            .encode_all(w)
            .map_err(Fail::Encode)?;

        // Éxito: dotdot es nuestro y no lo necesitamos (trivfs hace lo mismo).
        sys::port_deallocate(req.dotdot.name);
        Ok(())
    }

    /// Demuxer con la firma de libports/mach_msg_server, para encadenarlo con otro
    /// (p. ej. trivfs_demuxer) en el modo puente.
    ///
    /// # Safety
    /// `inp` debe apuntar a un mensaje recibido completo (msgh_size bytes) y `outp` a
    /// un buffer de al menos `out_cap` bytes que no se solape con `inp`.
    pub unsafe fn demux_raw(&mut self, inp: *mut sys::RawHeader, outp: *mut sys::RawHeader, out_cap: usize)
        -> boolean_t
    {
        // SAFETY: el llamante garantiza una cabecera válida.
        let head = unsafe { core::slice::from_raw_parts(inp.cast::<u8>(), HEADER_SIZE) };
        let Some(h) = sys::read_header(head) else { return MACH_BOOLEAN_FALSE };
        let len = (h.size as usize).max(HEADER_SIZE);
        // SAFETY: el kernel ha escrito msgh_size bytes; `outp` tiene out_cap bytes.
        let inb = unsafe { core::slice::from_raw_parts(inp.cast::<u8>(), len) };
        let outb = unsafe { core::slice::from_raw_parts_mut(outp.cast::<u8>(), out_cap) };
        if self.demux(inb, outb) { MACH_BOOLEAN_TRUE } else { MACH_BOOLEAN_FALSE }
    }

    /// Bucle de servicio de un solo hilo sobre `port` (un puerto o un port set), con la
    /// misma gestión de derechos que mach_msg_server de glibc.
    ///
    /// `idle_ms`: si no llega ningún mensaje en ese tiempo y no queda ninguna apertura
    /// viva, el bucle termina (un translator pasivo vuelve a arrancar cuando haga
    /// falta). Vuelve con KERN_SUCCESS tras un fsys_goaway aceptado o por inactividad.
    pub fn serve(&mut self, port: mach_port_t, idle_ms: Option<u32>) -> kern_return_t {
        let mut inb = sys::MsgBuf::new();
        let mut outb = sys::MsgBuf::new();
        let (opts, timeout) = match idle_ms {
            Some(ms) => (MACH_RCV_MSG | MACH_RCV_TIMEOUT, ms),
            None => (MACH_RCV_MSG, MACH_MSG_TIMEOUT_NONE),
        };
        loop {
            // SAFETY: buffer de MSG_MAX bytes alineado a 8.
            let kr = unsafe {
                mach_msg(inb.header_ptr(), opts, 0, sys::MSG_MAX as u32, port, timeout, MACH_PORT_NULL)
            };
            match kr {
                KERN_SUCCESS => {}
                MACH_RCV_TIMED_OUT if self.objects.is_empty() => return KERN_SUCCESS,
                MACH_RCV_TIMED_OUT | MACH_RCV_TOO_LARGE | MACH_RCV_INTERRUPTED => continue,
                other => return other,
            }

            self.demux(&inb.bytes, &mut outb.bytes);

            let Some(req) = sys::read_header(&inb.bytes) else { continue };
            let Some(rh) = sys::read_header(&outb.bytes) else { continue };
            let code = reply_code(&outb.bytes);

            // Error en una petición compleja: los derechos y la memoria que traía
            // siguen siendo nuestros; se destruyen (sin tocar el puerto de respuesta).
            if req.is_complex() && code != KERN_SUCCESS && code != MIG_NO_REPLY {
                let mut r = req;
                r.remote = MACH_PORT_NULL;
                sys::write_header(&mut inb.bytes, &r);
                unsafe { mach_msg_destroy(inb.header_ptr()) };
            }

            if rh.remote != MACH_PORT_NULL && code != MIG_NO_REPLY {
                let kr = unsafe {
                    mach_msg(outb.header_ptr(), MACH_SEND_MSG, rh.size, 0, MACH_PORT_NULL,
                             MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL)
                };
                if kr != KERN_SUCCESS {
                    // Respuesta no entregada: un MAKE_SEND que no llegó a hacerse no
                    // genera no-senders, así que la apertura creada se destruye aquí.
                    self.reply_undelivered();
                    if kr == MACH_SEND_INVALID_DEST && rh.is_complex() {
                        let mut r = rh;
                        r.remote = MACH_PORT_NULL;
                        sys::write_header(&mut outb.bytes, &r);
                        unsafe { mach_msg_destroy(outb.header_ptr()) };
                    }
                }
            } else if rh.remote == MACH_PORT_NULL {
                self.reply_undelivered();
            }

            if self.exit_requested {
                return KERN_SUCCESS;
            }
        }
    }

    /// Translator completo sin trivfs: fsys_startup con el padre y bucle de servicio.
    pub fn run_translator(&mut self, open_flags: i32, idle_ms: Option<u32>) -> kern_return_t {
        let ports = match fsys::startup(open_flags) {
            Ok(v) => v,
            Err(kr) => return kr,
        };
        self.realnode = Some(ports.realnode);
        let realnode = (!ports.realnode.is_null()).then_some(ports.realnode.name);
        self.enable_fsys(ports.set, ports.control, realnode);
        self.serve(ports.set, idle_ms)
    }
}

/// Permisos (O_READ|O_WRITE|O_EXEC) del usuario sobre el nodo subyacente, como
/// trivfs: io_restrict_auth con sus credenciales y file_check_access sobre el puerto
/// resultante.
fn check_access(realnode: mach_port_t, uids: &[u32], gids: &[u32]) -> Result<i32, kern_return_t> {
    struct Node(mach_port_t);
    impl RawClient for Node {
        fn port(&self) -> mach_port_t {
            self.0
        }
    }
    let code = |e: CallError| e.code();

    let restricted = fsys::io_restrict_auth(realnode, uids, gids).map_err(code)?;
    let perms: Result<i32, _> = Node(restricted.name).call(fsys::FILE_CHECK_ACCESS, ()).map_err(code);
    sys::port_deallocate(restricted.name);
    Ok(perms? & (O_READ | O_WRITE | O_EXEC))
}

/// Escribe cabecera + RetCode. `out` tiene al menos ERR_REPLY_SIZE bytes.
fn write_reply(out: &mut [u8], rh: &Header, code: kern_return_t) {
    sys::write_header(out, rh);
    let mut w = Writer::new(out, HEADER_SIZE);
    let _ = (code as i32).encode(&mut w);
}

/// RetCode de una respuesta ya construida.
pub fn reply_code(out: &[u8]) -> kern_return_t {
    let mut r = Reader::new(&out[..ERR_REPLY_SIZE], HEADER_SIZE, false);
    i32::decode(&mut r).unwrap_or(MIG_TYPE_ERROR) as kern_return_t
}
