//#[macro_use]

extern crate influx_db_client;

use influx_db_client::{Client, Point, Points, Value, Precision};
use std::time::Duration;
use std::net::UdpSocket;

struct KnxConnection {
    control_port: u16,
    control_socket: UdpSocket,
    tunneling_port: u16,
    tunneling_socket: UdpSocket,
    channel_id: u8,
}

impl KnxConnection {
    fn new() -> KnxConnection {

// TODO change to automatically finding IP!
        let port: u16 = get_available_udp_port().unwrap();
        let socket = UdpSocket::bind(("192.168.8.124", port)).expect("could not bind to port");
        socket.set_read_timeout(Some(Duration::new(1, 0))).expect("set_read_timeout call failed");

        let port2: u16 = get_available_udp_port().unwrap();
        let socket2 = UdpSocket::bind(("192.168.8.124", port2)).expect("could not bind to port");
        socket2.set_read_timeout(Some(Duration::new(1, 0))).expect("set_read_timeout call failed");
        KnxConnection{
            control_port: port,
            control_socket: socket,
            tunneling_port: port2,
            tunneling_socket: socket2,
            channel_id: 0,
        }
    }
    
    fn connect(&mut self) {
        let mut buf = [0; 26];

        buf[0] = 0x06; // header length
        buf[1] = 0x10; // knx version
        buf[2] = 0x02; // hi byte service descriptor (conn req)
        buf[3] = 0x05; // lo byte service descriptor (conn req)
        buf[4] = 0x00; // total length hi byte
        buf[5] = 0x1A; // total length lo byte

        buf[6] = 0x08; /* 08 - Host Protocol Address Information (HPAI) Lenght */
        buf[7] = 0x01; /* 01 - Host Protocol Address Information (HPAI) Lenght */
        buf[8] = 0xc0; /* c0 - IP address 00 = 192 */
        buf[9] = 0xa8; /* a8 - IP address 00 = 168 */
        buf[10] = 0x08; /* 0a - IP address 00 = 8 */
        buf[11] = 0x7c; /* 7c - IP address 00 = 124 */
        let portbytes = transform_u16_to_array_of_u8(self.control_port);
        buf[12] = portbytes[0]; /* xx - hi-byte local port number for CONNECTION, CONNECTIONSTAT and DISCONNECT requests */
        buf[13] = portbytes[1]; /* xx - lo-byte local port number for CONNECTION, CONNECTIONSTAT and DISCONNECT requests */

        buf[14] = 0x08; /* 08 - Host Protocol Address Information (HPAI) Lenght */
        buf[15] = 0x01; /* 01 - Host Protocol Address Information (HPAI) Lenght */
        buf[16] = 0xc0; /* c0 - IP address c0 = 192 */
        buf[17] = 0xa8; /* a8 - IP address a8 = 168 */
        buf[18] = 0x08; /* 0a - IP address 0a = 8 */
        buf[19] = 0x68; /* b3 - IP address 9F = 124 */
        let port2bytes = transform_u16_to_array_of_u8(self.tunneling_port);
        buf[20] = port2bytes[0]; /* yy - hi-byte local port number for TUNNELLING requests */
        buf[21] = port2bytes[1]; /* yy - lo-byte local port number for TUNNELLING requests */

        buf[22] = 0x04; /* structure len (4 bytes) */
        buf[23] = 0x04; /* Tunnel Connection */
        buf[24] = 0x02; /* KNX Layer (Tunnel Link Layer) */
        buf[25] = 0x00; /* Reserved */

        self.control_socket.send_to(&buf, "192.168.100.8:3671").expect("couldn't send buf!");

        let mut rbuf = [0; 128];
        let (amt, src) = self.control_socket.recv_from(&mut rbuf).unwrap();
        self.channel_id = rbuf[6];
        println!("{:?}", &rbuf[..amt]);
    }


/*
2e 00 b0 60 ff 0c 11 0d 00 80
2e 00 b0 60 ff 0c 11 0d 01 43 00
Ack
Resp
2e 00 b0 60 ff 0c 11 0d 00 c2
2e 00 b0 60 ff 0c 11 0d 01 47 80
ack
2e 00 b0 60 ff 0c 11 0d 00 81
*/


    fn send_tunnelreq(&self, knx_address: &str) {
        let mut treq = [0;21];
        treq[0] = 0x06; /* 06 - Header Length */
        treq[1] = 0x10; /* 10 - KNXnet version (1.0) */
        treq[2] = 0x04; /* 04 - hi-byte Service type descriptor (TUNNELLING_REQUEST) */
        treq[3] = 0x20; /* 20 - lo-byte Service type descriptor (TUNNELLING_REQUEST) */
        treq[4] = 0x00; /* 00 - hi-byte total length */
        treq[5] = 0x15; /* 15 - lo-byte total lengt 21 bytes */

        /* Connection Header (4 Bytes) */
        treq[6] = 0x04; /* 04 - Structure length */
        treq[7] = self.channel_id; /* given channel id */
        treq[8] = 0x00; /* sequence counter, zero if you send one tunnelling request only at this session, otherwise count ++ */
        treq[9] = 0x00; /* 00 - Reserved */

        /* cEMI-Frame (11 Bytes) */
        treq[10] = 0x11; /* message code, 11: Data Service transmitting */
        treq[11] = 0x00; /* add. info length (0 bytes) */
        treq[12] = 0xbc; /* control byte */
        treq[13] = 0xe0; /* DRL byte */
        treq[14] = 0x00; /* hi-byte source individual address */
        treq[15] = 0x00; /* lo-byte source (replace throw IP-Gateway) */

        let address_bytes = generate_knx_bytes_for_address(knx_address);

        treq[16] = address_bytes[0]; /* hi-byte destination address */
        treq[17] = address_bytes[1]; /* lo-Byte destination */
        treq[18] = 0x01; /* 01 data byte following */
        treq[19] = 0x00; /* tpdu */
        treq[20] = 0x81; /* 81: switch on, 80: off */
        println!("treq: {:?}", &treq);
        self.control_socket.send_to(&treq, "192.168.8.8:3671").expect("couldn't send treq!");

        let mut rbuf = [0; 128];
        let (amt, src) = self.tunneling_socket.recv_from(&mut rbuf).unwrap();
        println!("ack: {:?}", &rbuf[..amt]);
        let (amt, src) = self.tunneling_socket.recv_from(&mut rbuf).unwrap();
        println!("req: {:?}", &rbuf[..amt]);
        let iSequenceCounter = &rbuf[8];

        let mut tack = [0; 10];
        tack[0] = 0x06; /* 06 - Header Length */
        tack[1] = 0x10; /* 10 - KNXnet version (1.0) */
        tack[2] = 0x04; /* 04 - hi-byte Service type descriptor (TUNNELLING_ACK) */
        tack[3] = 0x21; /* 21 - lo-byte Service type descriptor (TUNNELLING_ACK) */
        tack[4] = 0x00; /* 00 - hi-byte total length */
        tack[5] = 0x0A; /* 0A - lo-byte total lengt 10 bytes */

        /* ConnectionHeader (4 Bytes) */
        tack[6] = 0x04; /* 04 - Structure length */
        tack[7] = self.channel_id; /* given channel id */
        tack[8] = iSequenceCounter & 0x01; /* 01 the sequence counter from 7th: receive a TUNNELLING_REQUEST */
        tack[9] = 0x00; /* 00 our error code */
        self.control_socket.send_to(&tack, "192.168.8.8:3671").expect("couldn't send tack");

    }
    fn send_tunnelreq2(&self, knx_address: &str) {
        let mut treq = [0;21];
        treq[0] = 0x06; /* 06 - Header Length */
        treq[1] = 0x10; /* 10 - KNXnet version (1.0) */
        treq[2] = 0x04; /* 04 - hi-byte Service type descriptor (TUNNELLING_REQUEST) */
        treq[3] = 0x20; /* 20 - lo-byte Service type descriptor (TUNNELLING_REQUEST) */
        treq[4] = 0x00; /* 00 - hi-byte total length */
        treq[5] = 0x15; /* 15 - lo-byte total lengt 21 bytes */

        /* Connection Header (4 Bytes) */
        treq[6] = 0x04; /* 04 - Structure length */
        treq[7] = self.channel_id; /* given channel id */
        treq[8] = 0x00; /* sequence counter, zero if you send one tunnelling request only at this session, otherwise count ++ */
        treq[9] = 0x00; /* 00 - Reserved */

        /* cEMI-Frame (11 Bytes) */
        treq[10] = 0x11; /* message code, 11: Data Service transmitting */
        treq[11] = 0x00; /* add. info length (0 bytes) */
        treq[12] = 0xbc; /* control byte */
        treq[13] = 0xe0; /* DRL byte */
        treq[14] = 0x00; /* hi-byte source individual address */
        treq[15] = 0x00; /* lo-byte source (replace throw IP-Gateway) */

        let address_bytes = generate_knx_bytes_for_address(knx_address);

        treq[16] = address_bytes[0]; /* hi-byte destination address */
        treq[17] = address_bytes[1]; /* lo-Byte destination */
        treq[18] = 0x01; /* 01 data byte following */
        treq[19] = 0x00; /* tpdu */
        treq[20] = 0x81; /* 81: switch on, 80: off */
        println!("treq: {:?}", &treq);
        self.control_socket.send_to(&treq, "192.168.8.8:3671").expect("couldn't send treq!");

        let mut rbuf = [0; 128];
        let (amt, src) = self.tunneling_socket.recv_from(&mut rbuf).unwrap();
        println!("ack: {:?}", &rbuf[..amt]);
        let (amt, src) = self.tunneling_socket.recv_from(&mut rbuf).unwrap();
        println!("req: {:?}", &rbuf[..amt]);
        let iSequenceCounter = &rbuf[8];

        let mut tack = [0; 10];
        tack[0] = 0x06; /* 06 - Header Length */
        tack[1] = 0x10; /* 10 - KNXnet version (1.0) */
        tack[2] = 0x04; /* 04 - hi-byte Service type descriptor (TUNNELLING_ACK) */
        tack[3] = 0x21; /* 21 - lo-byte Service type descriptor (TUNNELLING_ACK) */
        tack[4] = 0x00; /* 00 - hi-byte total length */
        tack[5] = 0x0A; /* 0A - lo-byte total lengt 10 bytes */

        /* ConnectionHeader (4 Bytes) */
        tack[6] = 0x04; /* 04 - Structure length */
        tack[7] = self.channel_id; /* given channel id */
        tack[8] = iSequenceCounter & 0x01; /* 01 the sequence counter from 7th: receive a TUNNELLING_REQUEST */
        tack[9] = 0x00; /* 00 our error code */
        self.control_socket.send_to(&tack, "192.168.8.8:3671").expect("couldn't send tack");

    }

    fn disconnect(&mut self) {
        /* DISCONNECT_REQUEST */

        let mut dcreq = [0;16];
        /* header */
        dcreq[0] = 0x06; /* 06 - Header Length */
        dcreq[1] = 0x10; /* 10 - KNXnet version (1.0) */
        dcreq[2] = 0x02; /* 02 - hi-byte Service type descriptor (DISCONNECT_REQUEST) */
        dcreq[3] = 0x09; /* 09 - lo-byte Service type descriptor (DISCONNECT_REQUEST) */
        dcreq[4] = 0x00; /* 00 - hi-byte total length */
        dcreq[5] = 0x10; /* 10 - lo-byte total lengt 16 Bytes */

        /* data (10 Bytes) */
        dcreq[6] = self.channel_id; /* given channel id */
        dcreq[7] = 0x00; /* 00 - */
        dcreq[8] = 0x08; /* 08 - Host Protocol Address Information (HPAI) Lenght */
        dcreq[9] = 0x01; /* 01 - Host Protocol Code 0x01 -> IPV4_UDP, 0x02 -> IPV6_TCP */

        dcreq[10] = 0xc0; /* c0 - IP address c0 = 192 */
        dcreq[11] = 0xa8; /* a8 - IP address a8 = 168 */
        dcreq[12] = 0x08; /* 0a - IP address 0a = 8 */
        dcreq[13] = 0x68; /* b3 - IP address 9F = 124 */

        let portbytes = transform_u16_to_array_of_u8(self.control_port);
        dcreq[14] = portbytes[0]; /* 0e - hi-byte local port number for CONNECTION, CONNECTIONSTAT and DISCONNECT requests */
        dcreq[15] = portbytes[1]; /* 57 - lo-byte local port number for CONNECTION, CONNECTIONSTAT and DISCONNECT requests */
        self.control_socket.send_to(&dcreq, "192.168.8.8:3671").expect("couldn't send dcreq");
        println!("sent disconnect!");
        let mut rbuf = [0; 128];
        let (amt, src) = self.control_socket.recv_from(&mut rbuf).unwrap();
        println!("dcreq ack: {:?}", &rbuf[..amt]);
        
        self.control_port = 0;
        self.tunneling_port = 0;

    }

}
// TODO: return value should be an Option!



fn main() {
    // default with "http://127.0.0.1:8086", db with "test"
    //let client = Client::new("http://192.168.8.4:8086", "smarthome");//.set_authentication("root", "root");

    // query, it's type is Option<Vec<Node>>
    //let _ = client.query("precision rfc3339", None);
//    let res = client.query("SELECT time, brightness, entity_id, state FROM /^light.*/ LIMIT 1", None).unwrap();


//    let res = client.query("SELECT * FROM /^light.*/ LIMIT 1", None).unwrap();
/*    let ser = &res.unwrap()[0].series;
    let dummy = vec!();
    let Ser = match ser {
            Some(X) => &X,
            None => &dummy
        };
    
    for light in Ser {
        println!("{:?}", light);
        println!("{:?}", light.values);
        println!("BLA");
    }
*/

    let mut connection = KnxConnection::new();
    connection.connect();
    connection.send_tunnelreq2("0/0/101");
    connection.disconnect();

    println!("finished execution");

}

fn generate_knx_bytes_for_address(address: &str) -> [u8; 2] {

     /* hi-byte destination address (20: group address) 4/0/0: (4*2048) + (0*256) + (0*1) = 8192 = 20 00 */
//        treq[17] = 0x65; /* lo-Byte destination */
    let v: Vec<u16> = address.split('/').map(|part| part.parse().unwrap()).collect();
    let value = (v[0] * 2048) + (v[1] * 256) + v[2];
    println!("{:?}", v);
    transform_u16_to_array_of_u8(value)
}

fn get_available_udp_port() -> Option<u16> {
    (1025..65535).find(|port| port_is_available(*port)
    )
}

fn port_is_available(port: u16) -> bool {
    match UdpSocket::bind(("192.168.8.124", port)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

fn transform_u16_to_array_of_u8(x:u16) -> [u8;2] {
    let b1 : u8 = ((x >> 8) & 0xff) as u8;
    let b2 : u8 = (x & 0xff) as u8;
    return [b1, b2]
}