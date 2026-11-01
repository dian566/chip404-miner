
import os, sys
# GitHub Actions miner — env: START, END, NEED
SALT=bytes.fromhex("445aa0838438a376563c290a2c15cf7ddea0883854555b68b0e01efefafff39a")
W=bytes.fromhex("ac45ab246f50eb16670f61ccdadfce2b8682a7b8")
import sha3
need=int(os.environ.get("NEED","40"))
start=int(os.environ.get("START","0"))
end=int(os.environ.get("END","2000000000"))
nbytes=need//8; rem=need%8
thresh=(0x100>>rem)-1 if rem else None
k=sha3.keccak_256(); base=SALT+W
for n in range(start,end):
    k2=k.copy(); k2.update(base+n.to_bytes(32,'big'))
    d=k2.digest()
    if d[:nbytes]==b"\0"*nbytes and (thresh is None or d[nbytes]<=thresh):
        print("FOUND", n)
        open("nonce.txt","w").write(str(n))
        sys.exit(0)
print("NOTFOUND", end-start)
