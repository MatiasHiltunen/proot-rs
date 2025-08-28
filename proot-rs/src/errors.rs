pub use nix::errno::Errno::{self, *};
use std::any::Any;
use std::io::Error as IOError;
use std::{
    fmt::{self, Display},
    result,
};
pub type Result<T> = result::Result<T, Error>;

/// This struct is an abstraction of exceptions encountered in the code. It is
/// inspired by [`anyhow`]. All type `E` which implements`std::error::Error` can
/// be converted to this `Error`. In addition, it contains an `errno` field,
/// which is useful in scenarios where errno value needs to be returned.
///
/// [`anyhow`]: https://docs.rs/anyhow/1.0.40/anyhow/

pub struct Error {
    errno: Errno,
    msg: Option<Box<dyn Display + Send + Sync + 'static>>,
    source: Option<Box<dyn std::error::Error>>,
}

#[allow(dead_code)]
impl Error {
    /// Create an Error with a unknown errno
    pub fn unknown() -> Self {
        Error::errno(Errno::UnknownErrno)
    }

    /// Create an Error with the specific errno
    pub fn errno(errno: Errno) -> Self {
        Error {
            errno: errno,
            msg: None,
            source: None,
        }
    }

    /// Create an Error with the specific message
    pub fn msg<M>(msg: M) -> Self
    where
        M: Display + Send + Sync + 'static,
    {
        Error::errno_with_msg(Errno::UnknownErrno, msg)
    }

    /// Create an Error with the specific errno and message
    pub fn errno_with_msg<M>(errno: Errno, msg: M) -> Self
    where
        M: Display + Send + Sync + 'static,
    {
        Error {
            errno: errno,
            msg: Some(Box::new(msg)),
            source: None,
        }
    }

    /// Set errno of self to a specific errno, and return this Error.
    pub fn with_errno(mut self, errno: Errno) -> Self {
        self.errno = errno;
        self
    }

    /// Set message of self to a specific message, and return this Error.
    pub fn with_msg<M>(mut self, msg: M) -> Self
    where
        M: Display + Send + Sync + 'static,
    {
        self.msg = Some(Box::new(msg));
        self
    }

    /// Get errno of this Error. If errno is not set, the default value is
    /// `UnknownErrno`.
    pub fn get_errno(&self) -> Errno {
        self.errno
    }
}

#[allow(dead_code)]
impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error with {}({})", self.errno, self.errno as i32)?;

        if let Some(msg) = &self.msg {
            write!(f, ", msg: {}", msg)?;
        }
        if let Some(source) = &self.source {
            write!(f, ", source: {}", source)?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Error");
        d.field("errno", &self.errno);
        match self.msg.as_ref() {
            Some(msg) => d.field("msg", &Some(format_args!("{}", msg))),
            None => d.field("msg", &Option::<()>::None),
        };
        d.field("source", &self.source).finish()
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.errno == other.errno
    }
}

// Note: We rely on the generic `From<E>` below for converting `nix::errno::Errno`
// which implements `std::error::Error`.


// Generic conversion from any error type. On stable Rust we cannot use
// specialization, so we perform a best-effort downcast to `std::io::Error`
// to recover an errno when possible, and fall back to `UnknownErrno`.
impl<E> From<E> for Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(error: E) -> Self {
        // Try to extract a meaningful errno when the incoming error is
        // actually an `std::io::Error`.
        let errno = {
            // Cast to `&dyn Any` to attempt a downcast.
            let any_ref = &error as &dyn Any;
            if let Some(ioe) = any_ref.downcast_ref::<IOError>() {
                match ioe.raw_os_error() {
                    Some(code) => Errno::from_i32(code),
                    None => Errno::UnknownErrno,
                }
            } else {
                Errno::UnknownErrno
            }
        };

        Error {
            errno,
            msg: None,
            source: Some(Box::new(error)),
        }
    }
}

/// This trait is something like [`anyhow::Context`], which provide
/// `with_context()` and `context()` function to attach a message to
/// `Result<T,E>`, In addition, it also allows appending an `errno` value.
///
/// [`anyhow::Context`]: https://docs.rs/anyhow/1.0.40/anyhow/trait.Context.html
#[allow(dead_code)]
pub trait WithContext<T> {
    fn errno(self, errno: Errno) -> Result<T>;

    fn context<C>(self, context: C) -> Result<T>
    where
        C: Display + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C;
}

#[allow(dead_code)]
impl<T, E> WithContext<T> for result::Result<T, E>
where
    E: Into<Error>,
{
    fn errno(self, errno: Errno) -> Result<T> {
        self.map_err(|error| Into::<Error>::into(error).with_errno(errno))
    }

    fn context<C>(self, context: C) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
    {
        self.map_err(|error| Into::<Error>::into(error).with_msg(context))
    }

    fn with_context<C, F>(self, f: F) -> Result<T>
    where
        C: Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        match self {
            Ok(t) => Ok(t),
            Err(e) => Err(e).context(f()),
        }
    }
}
