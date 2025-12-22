import socket
import time

def tcp_probe(host , port ,  payload:bytes="" ,timeout_ms=5000 , tcpwrappedms=3000):
    timeout = timeout_ms/1000.0
    tcp_wrapped = tcpwrappedms/1000.0
    s=socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    s.settimeout(timeout)
    
    try:
        s.connect((host,port))
        if payload:
            s.sendall(payload)
        
        chunks=[]
        start = time.time()
        while True:
            remaining_time = timeout-(time.time()-start)
            if remaining_time<=0:
                break
            s.settimeout(remaining_time)
            try:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break

        tcp_wrap=False
        if(time.time()-start<=tcp_wrapped and chunks==[]):
            tcp_wrap = True
        
        raw = b"".join(chunks)
        return {
            "tcp_wrapped" : tcp_wrap,
            "peer_name": s.getpeername(),
            "raw_bytes": raw,
            "response": raw.decode(errors="ignore"),
        }
    except OSError:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass
        
def udp_probe(host, port , payload:bytes="" , timeout_ms = 5000 , max_tries=1):
    timeout = timeout_ms/1000.0
    s=socket.socket(socket.AF_INET , socket.SOCK_DGRAM)
    s.settimeout(timeout)
    addr = (host,port)
    
    try:
        raw=b""
        for _ in range(max_tries):
            s.sendto(payload, addr)
            try:
                data, peer = s.recvfrom(4096)
                raw += data
                break 
            except socket.timeout:
                continue

        return {
            "peer_name": addr,
            "raw_bytes": raw,
            "response": raw.decode(errors="ignore"),
        }
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass