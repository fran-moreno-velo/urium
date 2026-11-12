//===================================================================================//
// symlink: enlace simbólico como translator, sin trivfs ni libports                 //
//===================================================================================//
//
//   settrans -c enlace ./symlink DESTINO
//
// Como el original: se marca como proceso importante, y termina tras 10 minutos sin
// mensajes (si es pasivo, el padre lo vuelve a arrancar en la siguiente búsqueda).
// A diferencia del original, se marca ANTES de responder al padre, para no decir
// "estoy listo" y salir a continuación si falla.

use std::process::ExitCode;

use hurd_raw::gnumach::port::{mach_port_t, MACH_PORT_NULL};
use hurd_raw::rawrpc::sys::{self, errno, KERN_SUCCESS};
use hurd_raw::rawrpc::{CallError, RawClient, RawServer};
use hurd_raw::symlink::{Symlink, PROC_MARK_IMPORTANT};

const IDLE_MS: u32 = 10 * 60 * 1000;

const USAGE: &str = "uso: symlink DESTINO\n\
Un enlace simbólico es un alias de otro nodo del sistema de ficheros. Se refiere al\n\
destino por su nombre, que se busca en el espacio de nombres del cliente.";

unsafe extern "C" {
  // glibc (hurd.h): puerto del servidor de procesos de esta tarea.
  fn getproc() -> mach_port_t;
}

struct Proc(mach_port_t);
impl RawClient for Proc {
  fn port(&self) -> mach_port_t {
    self.0
  }
}

fn main() -> ExitCode {
  let args: Vec<String> = std::env::args().collect();
  let target = match args.as_slice() {
    [_, a] if a == "--help" || a == "-?" => {
      println!("{USAGE}");
      return ExitCode::SUCCESS;
    }
    [_, a] if a == "--version" || a == "-V" => {
      println!("symlink (hurd-raw) {}", env!("CARGO_PKG_VERSION"));
      return ExitCode::SUCCESS;
    }
    [_, t] => t,
    _ => {
      eprintln!("{USAGE}");
      return ExitCode::from(64);
    }
  };
  let link = match Symlink::new(target) {
    Ok(l) => l,
    Err(e) => {
      eprintln!("symlink: {e}");
      return ExitCode::from(64);
    }
  };

  // Marcarse como importante. EPERM o un servidor de procesos antiguo que no conoce
  // la RPC (MIG_BAD_ID) se ignoran, como en el original.
  let proc = unsafe { getproc() };
  if proc == MACH_PORT_NULL {
    eprintln!("symlink: no se puede obtener el puerto del servidor de procesos");
    return ExitCode::from(2);
  }
  let res: Result<(), CallError> = Proc(proc).call(PROC_MARK_IMPORTANT, ());
  sys::port_deallocate(proc);
  match res {
    Ok(()) | Err(CallError::Server(errno::EPERM)) | Err(CallError::Server(sys::MIG_BAD_ID)) => {}
    Err(e) => {
      eprintln!("symlink: no se puede marcar como importante: {:#x}", e.code());
      return ExitCode::from(2);
    }
  }

  let mut server = RawServer::new(link);
  match server.run_translator(0, Some(IDLE_MS)) {
    KERN_SUCCESS => ExitCode::SUCCESS,
    kr => {
      eprintln!("symlink: error {kr:#x} (¿se ha arrancado con settrans?)");
      ExitCode::FAILURE
    }
  }
}
