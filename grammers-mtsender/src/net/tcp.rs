// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use log::info;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::ServerAddr;

pub enum NetStream {
    Tcp(TcpStream),
    #[cfg(feature = "proxy")]
    ProxySocks5(tokio_socks::tcp::Socks5Stream<TcpStream>),
    #[cfg(feature = "mtproxy")]
    MtProxy(TcpStream),
    #[cfg(feature = "mtproxy")]
    MtProxyFakeTls(grammers_mtproto::tls::FakeTlsStream<TcpStream>),
}

impl AsyncRead for NetStream {
    #[allow(unused_mut)]
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "proxy")]
            Self::ProxySocks5(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "mtproxy")]
            Self::MtProxy(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "mtproxy")]
            Self::MtProxyFakeTls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for NetStream {
    #[allow(unused_mut)]
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "proxy")]
            Self::ProxySocks5(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "mtproxy")]
            Self::MtProxy(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "mtproxy")]
            Self::MtProxyFakeTls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    #[allow(unused_mut)]
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "proxy")]
            Self::ProxySocks5(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "mtproxy")]
            Self::MtProxy(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "mtproxy")]
            Self::MtProxyFakeTls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    #[allow(unused_mut)]
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "proxy")]
            Self::ProxySocks5(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "mtproxy")]
            Self::MtProxy(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "mtproxy")]
            Self::MtProxyFakeTls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl NetStream {
    pub(crate) fn split(
        &mut self,
    ) -> (
        tokio::io::ReadHalf<&mut Self>,
        tokio::io::WriteHalf<&mut Self>,
    ) {
        tokio::io::split(self)
    }

    pub(crate) async fn connect(addr: &ServerAddr) -> Result<Self, std::io::Error> {
        info!("connecting...");
        match addr {
            ServerAddr::Tcp { address } => Ok(NetStream::Tcp(TcpStream::connect(address).await?)),
            #[cfg(feature = "proxy")]
            ServerAddr::Proxied { address, proxy } => {
                Self::connect_proxy_stream(address, proxy).await
            }
            #[cfg(feature = "mtproxy")]
            ServerAddr::MtProxy {
                proxy_host,
                proxy_port,
                secret,
                dc_id,
            } => {
                Self::connect_mtproxy_stream(proxy_host, *proxy_port, secret, *dc_id).await
            }
        }
    }

    #[cfg(feature = "mtproxy")]
    async fn connect_mtproxy_stream(
        host: &str,
        port: u16,
        secret: &str,
        dc_id: i32,
    ) -> Result<NetStream, std::io::Error> {
        use tokio::net::lookup_host;

        info!("connecting to MTProxy at {}:{}", host, port);

        let addrs = lookup_host((host, port)).await.map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("failed to resolve MTProxy host {}: {}", host, e),
            )
        })?;

        let addr = addrs.into_iter().next().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no addresses found for MTProxy host {}", host),
            )
        })?;

        let tcp = TcpStream::connect(addr).await?;

        // Parse secret to determine mode
        let parsed = grammers_mtproto::transport::parse_secret(secret)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        match parsed {
            grammers_mtproto::transport::ProxySecret::Faketls { key, domain } => {
                info!("FakeTLS mode: connecting to {} with domain {}", host, domain);
                let faketls = grammers_mtproto::tls::FakeTlsStream::new(
                    tcp,
                    &key,
                    dc_id as i16,
                    &domain,
                )
                .await?;
                Ok(NetStream::MtProxyFakeTls(faketls))
            }
            _ => {
                // Simple or Secured — use raw TcpStream (MtProxy transport handles obfuscation)
                Ok(NetStream::MtProxy(tcp))
            }
        }
    }

    #[cfg(feature = "proxy")]
    async fn connect_proxy_stream(
        addr: &std::net::SocketAddr,
        proxy_url: &str,
    ) -> Result<NetStream, std::io::Error> {
        use std::{
            io::{self, ErrorKind},
            net::{IpAddr, SocketAddr},
        };

        use hickory_resolver::Resolver;
        use url::Host;

        let proxy = url::Url::parse(proxy_url)
            .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;
        let scheme = proxy.scheme();
        let host = proxy.host().ok_or(io::Error::new(
            ErrorKind::NotFound,
            format!("proxy host is missing from url: {}", proxy_url),
        ))?;
        let port = proxy.port().ok_or(io::Error::new(
            ErrorKind::NotFound,
            format!("proxy port is missing from url: {}", proxy_url),
        ))?;
        let username = proxy.username();
        let password = proxy.password().unwrap_or("");
        let socks_addr = match host {
            Host::Domain(domain) => {
                let resolver = Resolver::builder_tokio().unwrap().build();
                let response = resolver.lookup_ip(domain).await?;
                let socks_ip_addr = response.into_iter().next().ok_or(io::Error::new(
                    ErrorKind::NotFound,
                    format!("proxy host did not return any ip address: {}", domain),
                ))?;
                SocketAddr::new(socks_ip_addr, port)
            }
            Host::Ipv4(v4) => SocketAddr::new(IpAddr::from(v4), port),
            Host::Ipv6(v6) => SocketAddr::new(IpAddr::from(v6), port),
        };

        match scheme {
            "socks5" => {
                if username.is_empty() {
                    Ok(NetStream::ProxySocks5(
                        tokio_socks::tcp::Socks5Stream::connect(socks_addr, addr)
                            .await
                            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?,
                    ))
                } else {
                    Ok(NetStream::ProxySocks5(
                        tokio_socks::tcp::Socks5Stream::connect_with_password(
                            socks_addr, addr, username, password,
                        )
                        .await
                        .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?,
                    ))
                }
            }
            scheme => Err(io::Error::new(
                ErrorKind::ConnectionAborted,
                format!("proxy scheme not supported: {}", scheme),
            )),
        }
    }
}
