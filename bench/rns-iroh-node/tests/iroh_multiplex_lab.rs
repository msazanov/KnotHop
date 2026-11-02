//! Local transport feasibility only: this is not an authorization or VPN test.
use std::{net::SocketAddr, time::Duration};

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey};

const ALPN: &[u8] = b"knothop-multiplex-lab/0";

async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))
        .unwrap()
        .bind()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_connection_carries_stream_and_datagrams_bidirectionally() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let server = endpoint().await;
        let client = endpoint().await;
        let addr = EndpointAddr::new(server.id()).with_ip_addr(SocketAddr::from((
            [127, 0, 0, 1],
            server.bound_sockets()[0].port(),
        )));
        let incoming = async { server.accept().await.unwrap().await.unwrap() };
        let (client_conn, server_conn) = tokio::join!(client.connect(addr, ALPN), incoming);
        let client_conn = client_conn.unwrap();
        assert_eq!(client_conn.remote_id(), server.id());
        assert_eq!(server_conn.remote_id(), client.id());

        let (mut client_send, mut client_recv) = client_conn.open_bi().await.unwrap();
        client_send.write_all(b"control-request").await.unwrap();
        client_send.finish().unwrap();
        client_conn.send_datagram(bytes::Bytes::from_static(b"data-request")).unwrap();

        let (mut server_send, mut server_recv) = server_conn.accept_bi().await.unwrap();
        assert_eq!(server_recv.read_to_end(128).await.unwrap(), b"control-request");
        assert_eq!(server_conn.read_datagram().await.unwrap(), &b"data-request"[..]);
        server_send.write_all(b"control-response").await.unwrap();
        server_send.finish().unwrap();
        server_conn.send_datagram(bytes::Bytes::from_static(b"data-response")).unwrap();
        assert_eq!(client_recv.read_to_end(128).await.unwrap(), b"control-response");
        assert_eq!(client_conn.read_datagram().await.unwrap(), &b"data-response"[..]);
        client_conn.close(0u32.into(), b"done");
        client.close().await;
        server.close().await;
    })
    .await
    .expect("local multiplex test timed out");
}
