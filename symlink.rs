//===================================================================================//
// symlink: enlace simbólico como translator (hurd/trans/symlink.c) sobre rawrpc     //
//===================================================================================//
//
//   settrans -c enlace /hurd/symlink DESTINO
//
// No sirve ningún fichero: sólo contesta fsys_getroot diciendo al cliente que repita
// la búsqueda con otro nombre, que se resuelve en el espacio de nombres del CLIENTE.
//
//   destino absoluto  FS_RETRY_MAGICAL  "/..."  sin puerto   (desde la raíz del cliente)
//   destino relativo  FS_RETRY_REAUTH   destino dotdot       (desde el directorio del enlace)
//   O_NOLINK          FS_RETRY_REAUTH   ""      nodo propio  (el enlace en sí, sin credenciales)
//
// Diferencias deliberadas con el original:
//   1. El original copia el destino con strcpy en un string_t de 1024 bytes: un
//      destino más largo desborda la respuesta. Aquí se rechaza al arrancar.
//   2. El original no libera dotdot cuando no lo devuelve (destino absoluto y
//      O_NOLINK): pierde una referencia por búsqueda. rawrpc lo libera.
//   3. Si io_restrict_auth falla al arrancar, el original devuelve MACH_PORT_NULL a
//      las búsquedas con O_NOLINK; aquí devuelven EIO.

use crate::gnumach::kern_return::kern_return_t;
use crate::gnumach::port::mach_port_t;
use crate::rawrpc::fsys::{self, Getroot, GetrootRequest, RetryPort};
use crate::rawrpc::sys::{errno, oflags};
use crate::rawrpc::{MsgId, Port, RawTranslator, Services};

/// string_t = c_string[1024]: el destino más su NUL tienen que caber.
pub const MAX_TARGET: usize = 1023;

pub struct Symlink {
    target: String,
    /// Nodo subyacente sin credenciales (io_restrict_auth con uids/gids vacíos).
    node_noauth: Option<mach_port_t>,
}

impl Symlink {
    pub fn new(target: &str) -> Result<Self, String> {
        if target.is_empty() {
            return Err("el destino está vacío".into());
        }
        if target.len() > MAX_TARGET {
            return Err(format!("el destino tiene {} bytes; el máximo es {MAX_TARGET}", target.len()));
        }
        if target.contains('\0') {
            return Err("el destino contiene un byte nulo".into());
        }
        Ok(Symlink { target: target.to_string(), node_noauth: None })
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn node_noauth(&self) -> Option<mach_port_t> {
        self.node_noauth
    }
}

impl RawTranslator for Symlink {
    /// Sin servicios propios: sólo habla fsys por el puerto de control.
    const BASE_ID: MsgId = 0;

    fn services() -> Services<Self> {
        Services::new()
    }

    fn on_startup(&mut self, realnode: Option<mach_port_t>) {
        self.node_noauth = realnode.and_then(|node| match fsys::io_restrict_auth(node, &[], &[]) {
            Ok(p) => Some(p.name),
            Err(e) => {
                eprintln!("symlink: io_restrict_auth sobre el nodo: {:#x}", e.code());
                None
            }
        });
    }

    fn getroot(&mut self, req: &GetrootRequest) -> Result<Getroot, kern_return_t> {
        if req.flags & oflags::O_NOLINK != 0 {
            // El enlace en sí (para lstat, etc.): el nodo subyacente sin credenciales,
            // que el cliente tiene que reautenticar.
            let node = self.node_noauth.ok_or(errno::EIO)?;
            return Ok(Getroot::Retry {
                retry: fsys::FS_RETRY_REAUTH,
                name: String::new(),
                port: RetryPort::Send(Port::copy_send(node)),
            });
        }
        Ok(if self.target.starts_with('/') {
            Getroot::Retry { retry: fsys::FS_RETRY_MAGICAL, name: self.target.clone(), port: RetryPort::Null }
        } else {
            Getroot::Retry { retry: fsys::FS_RETRY_REAUTH, name: self.target.clone(), port: RetryPort::Dotdot }
        })
    }

    // fsys_goaway: el valor por defecto (aceptar y terminar) es lo que hace el original.
    // fsys_syncfs: el valor por defecto (no hacer nada) también.
}

/// proc_mark_important (process.defs, 24053): que el servidor de procesos trate
/// este proceso como esencial, igual que el original.
pub const PROC_MARK_IMPORTANT: MsgId = 24053;
