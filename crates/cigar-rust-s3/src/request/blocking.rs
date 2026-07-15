extern crate base64;
extern crate md5;

use std::io;
use std::io::{Read, Write};

use attohttpc::header::HeaderName;

use crate::bucket::Bucket;
use crate::command::Command;
use crate::error::S3Error;
use crate::utils::now_utc;
use bytes::Bytes;
use std::collections::HashMap;
use time::OffsetDateTime;

use crate::command::HttpMethod;
use crate::request::{Request, ResponseData};

const MAX_LIST_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

fn hardened_session() -> attohttpc::Session {
    let mut session = attohttpc::Session::new();
    session.proxy_settings(attohttpc::ProxySettings::builder().build());
    session.follow_redirects(false);
    session
}

fn read_bounded_response<R: Read>(reader: R, maximum: usize) -> Result<Bytes, S3Error> {
    let limit = u64::try_from(maximum)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "response limit is invalid"))?;
    let mut bounded = reader.take(limit.saturating_add(1));
    let mut body = Vec::new();
    bounded.read_to_end(&mut body)?;
    if body.len() > maximum {
        return Err(S3Error::Io(io::Error::new(
            io::ErrorKind::FileTooLarge,
            "list response exceeds the configured bound",
        )));
    }
    Ok(Bytes::from(body))
}

// Temporary structure for making a request
pub struct AttoRequest<'a> {
    pub bucket: &'a Bucket,
    pub path: &'a str,
    pub command: Command<'a>,
    pub datetime: OffsetDateTime,
    pub sync: bool,
}

impl<'a> Request for AttoRequest<'a> {
    type Response = attohttpc::Response;
    type HeaderMap = attohttpc::header::HeaderMap;

    fn datetime(&self) -> OffsetDateTime {
        self.datetime
    }

    fn bucket(&self) -> Bucket {
        self.bucket.clone()
    }

    fn command(&self) -> Command<'_> {
        self.command.clone()
    }

    fn path(&self) -> String {
        self.path.to_string()
    }

    fn response(&self) -> Result<Self::Response, S3Error> {
        // Build headers
        let headers = self.headers()?;

        let mut session = hardened_session();

        for (name, value) in headers.iter() {
            session.header(HeaderName::from_bytes(name.as_ref())?, value.to_str()?);
        }

        if let Some(timeout) = self.bucket.request_timeout {
            session.timeout(timeout)
        }

        let request = match self.command.http_verb() {
            HttpMethod::Get => session.get(self.url()?),
            HttpMethod::Delete => session.delete(self.url()?),
            HttpMethod::Put => session.put(self.url()?),
            HttpMethod::Post => session.post(self.url()?),
            HttpMethod::Head => session.head(self.url()?),
        };

        let response = request.bytes(&self.request_body()?).send()?;

        if cfg!(feature = "fail-on-err") && !response.status().is_success() {
            let status = response.status().as_u16();
            let text = response.text()?;
            return Err(S3Error::HttpFailWithBody(status, text));
        }

        Ok(response)
    }

    fn response_status(&self) -> Result<u16, S3Error> {
        crate::retry! {
            {
                let headers = self.headers()?;
                let mut session = hardened_session();

                for (name, value) in headers.iter() {
                    session.header(HeaderName::from_bytes(name.as_ref())?, value.to_str()?);
                }

                if let Some(timeout) = self.bucket.request_timeout {
                    session.timeout(timeout)
                }

                let request = match self.command.http_verb() {
                    HttpMethod::Get => session.get(self.url()?),
                    HttpMethod::Delete => session.delete(self.url()?),
                    HttpMethod::Put => session.put(self.url()?),
                    HttpMethod::Post => session.post(self.url()?),
                    HttpMethod::Head => session.head(self.url()?),
                };

                let response = request.bytes(&self.request_body()?).send()?;
                let status = response.status().as_u16();

                if status == 404 {
                    Ok(status)
                } else if cfg!(feature = "fail-on-err") && !response.status().is_success() {
                    let text = response.text()?;
                    Err(S3Error::HttpFailWithBody(status, text))
                } else {
                    Ok(status)
                }
            }
        }
    }

    fn response_data(&self, etag: bool) -> Result<ResponseData, S3Error> {
        let response = crate::retry! {self.response()}?;
        let status_code = response.status().as_u16();

        let response_headers = response
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string(),
                    v.to_str()
                        .unwrap_or("could-not-decode-header-value")
                        .to_string(),
                )
            })
            .collect::<HashMap<String, String>>();

        // When etag=true, we extract the ETag header and return it as the body.
        // This is used for PUT operations (regular puts, multipart chunks) where:
        // 1. S3 returns an empty or non-useful response body
        // 2. The ETag header contains the essential information we need
        // 3. The calling code expects to get the ETag via response_data.as_str()
        //
        // Note: This approach means we discard any actual response body when etag=true,
        // but for the operations that use this (PUTs), the body is typically empty
        // or contains redundant information already available in headers.
        //
        // Compatibility note: returning the response body separately from the ETag
        // requires an upstream breaking API change; preserve the current contract here.
        let body_vec = if etag {
            if let Some(etag) = response.headers().get("ETag") {
                Bytes::from(etag.to_str()?.to_string())
            } else {
                Bytes::from("")
            }
        } else if matches!(
            &self.command,
            Command::ListObjects { .. } | Command::ListObjectsV2 { .. }
        ) {
            read_bounded_response(response, MAX_LIST_RESPONSE_BYTES)?
        } else {
            // HEAD requests don't have a response body
            if self.command.http_verb() == HttpMethod::Head {
                Bytes::from("")
            } else {
                Bytes::from(response.bytes()?)
            }
        };
        Ok(ResponseData::new(body_vec, status_code, response_headers))
    }

    fn response_data_to_writer<T: Write + ?Sized>(&self, writer: &mut T) -> Result<u16, S3Error> {
        let mut response = crate::retry! {self.response()}?;

        let status_code = response.status();
        io::copy(&mut response, writer)?;

        Ok(status_code.as_u16())
    }

    fn response_header(&self) -> Result<(Self::HeaderMap, u16), S3Error> {
        let response = crate::retry! {self.response()}?;
        let status_code = response.status().as_u16();
        let headers = response.headers().clone();
        Ok((headers, status_code))
    }
}

impl<'a> AttoRequest<'a> {
    pub fn new<'b>(
        bucket: &'b Bucket,
        path: &'b str,
        command: Command<'b>,
    ) -> Result<AttoRequest<'b>, S3Error> {
        bucket.credentials_refresh()?;
        Ok(AttoRequest {
            bucket,
            path,
            command,
            datetime: now_utc(),
            sync: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{hardened_session, read_bounded_response};
    use crate::bucket::Bucket;
    use crate::command::Command;
    use crate::request::Request;
    use crate::request::blocking::AttoRequest;
    use anyhow::Result;
    use awscreds::Credentials;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::process::Command as ProcessCommand;
    use std::time::{Duration, Instant};

    // Fake keys - otherwise using Credentials::default will use actual user
    // credentials if they exist.
    fn fake_credentials() -> Credentials {
        let access_key = "example-access-key";
        let secert_key = "example-secret-key";
        Credentials::new(Some(access_key), Some(secert_key), None, None, None).unwrap()
    }

    #[test]
    fn list_response_reader_enforces_exact_aggregate_bound() {
        assert_eq!(
            read_bounded_response(std::io::Cursor::new(vec![0x5a; 4]), 4)
                .unwrap()
                .len(),
            4
        );
        assert!(read_bounded_response(std::io::Cursor::new(vec![0x5a; 5]), 4).is_err());
    }

    #[test]
    fn hardened_session_ignores_hostile_environment_child() -> Result<()> {
        let Ok(url) = std::env::var("CIGAR_S3_HARDENED_SESSION_TEST_URL") else {
            return Ok(());
        };
        let response = hardened_session().get(url).send()?;
        assert_eq!(response.status().as_u16(), 200);
        Ok(())
    }

    #[test]
    fn hardened_session_ignores_hostile_proxy_and_netrc_environment() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let server = std::thread::spawn(move || -> std::io::Result<String> {
            let deadline = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "hardened client did not connect directly",
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut request = vec![0_u8; 16 * 1024];
            let length = stream.read(&mut request)?;
            let request = String::from_utf8_lossy(&request[..length]).into_owned();
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )?;
            Ok(request)
        });

        let home = tempfile::tempdir()?;
        std::fs::write(
            home.path().join(".netrc"),
            "machine 127.0.0.1 login ambient-user password ambient-secret\n",
        )?;
        let output = ProcessCommand::new(std::env::current_exe()?)
            .arg("hardened_session_ignores_hostile_environment_child")
            .arg("--nocapture")
            .env(
                "CIGAR_S3_HARDENED_SESSION_TEST_URL",
                format!("http://{address}/"),
            )
            .env("HOME", home.path())
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("https_proxy", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .env("all_proxy", "http://127.0.0.1:1")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy")
            .output()?;
        assert!(
            output.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let request = server
            .join()
            .map_err(|_| std::io::Error::other("origin server panicked"))??;
        let lowercase = request.to_ascii_lowercase();
        assert!(!lowercase.contains("proxy-authorization:"));
        assert!(!lowercase.contains("authorization:"));
        Ok(())
    }

    #[test]
    fn url_uses_https_by_default() -> Result<()> {
        let region = "custom-region".parse()?;
        let bucket = Bucket::new("my-first-bucket", region, fake_credentials())?;
        let path = "/my-first/path";
        let request = AttoRequest::new(&bucket, path, Command::GetObject).unwrap();

        assert_eq!(request.url()?.scheme(), "https");

        let headers = request.headers().unwrap();
        let host = headers.get("Host").unwrap();

        assert_eq!(*host, "my-first-bucket.custom-region".to_string());
        Ok(())
    }

    #[test]
    fn url_uses_https_by_default_path_style() -> Result<()> {
        let region = "custom-region".parse()?;
        let bucket = Bucket::new("my-first-bucket", region, fake_credentials())?.with_path_style();
        let path = "/my-first/path";
        let request = AttoRequest::new(&bucket, path, Command::GetObject).unwrap();

        assert_eq!(request.url()?.scheme(), "https");

        let headers = request.headers().unwrap();
        let host = headers.get("Host").unwrap();

        assert_eq!(*host, "custom-region".to_string());
        Ok(())
    }

    #[test]
    fn url_uses_scheme_from_custom_region_if_defined() -> Result<()> {
        let region = "http://custom-region".parse()?;
        let bucket = Bucket::new("my-second-bucket", region, fake_credentials())?;
        let path = "/my-second/path";
        let request = AttoRequest::new(&bucket, path, Command::GetObject).unwrap();

        assert_eq!(request.url()?.scheme(), "http");

        let headers = request.headers().unwrap();
        let host = headers.get("Host").unwrap();
        assert_eq!(*host, "my-second-bucket.custom-region".to_string());
        Ok(())
    }

    #[test]
    fn url_uses_scheme_from_custom_region_if_defined_with_path_style() -> Result<()> {
        let region = "http://custom-region".parse()?;
        let bucket = Bucket::new("my-second-bucket", region, fake_credentials())?.with_path_style();
        let path = "/my-second/path";
        let request = AttoRequest::new(&bucket, path, Command::GetObject).unwrap();

        assert_eq!(request.url()?.scheme(), "http");

        let headers = request.headers().unwrap();
        let host = headers.get("Host").unwrap();
        assert_eq!(*host, "custom-region".to_string());

        Ok(())
    }

    #[test]
    fn head_object_omits_body_headers_from_request_and_signature() -> Result<()> {
        let region = "custom-region".parse()?;
        let bucket = Bucket::new("my-first-bucket", region, fake_credentials())?;
        let request = AttoRequest::new(&bucket, "/my-first/path", Command::HeadObject).unwrap();

        let headers = request.headers().unwrap();

        assert!(!headers.contains_key("Content-Length"));
        assert!(!headers.contains_key("Content-Type"));
        assert!(headers.contains_key("x-amz-content-sha256"));

        let authorization = headers.get("Authorization").unwrap().to_str()?;
        let signed_headers = authorization
            .split("SignedHeaders=")
            .nth(1)
            .and_then(|value| value.split(',').next())
            .unwrap();

        assert!(!signed_headers.contains("content-length"));
        assert!(!signed_headers.contains("content-type"));

        Ok(())
    }
}
