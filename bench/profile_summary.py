import sys, collections
CATS=[("sha256 (хеши пакетов/частей)", ("Hashes.py",)),("HMAC", ("HMAC.py","verify_hmac")),("AES", ("AES.py",)),
      ("чтение/запись сокета (TCPInterface)", ("TCPInterface.py",)),("прочее Resource/Link/Transport", ("Resource.py","Link.py","Transport.py","Packet.py","Identity.py","Token.py"))]
for name in sys.argv[1:]:
    tot=0; cat=collections.Counter(); leaf=collections.Counter()
    for line in open(name):
        line=line.rstrip()
        if not line: continue
        stack,_,n=line.rpartition(' '); n=int(n); tot+=n; fr=stack.split(';')
        leaf[fr[-1]]+=n
        for c,keys in CATS:
            if any(k in fr[-1] for k in keys): cat[c]+=n; break
        else: cat["остальное"]+=n
    print("=====",name.split('/')[-1],"| сэмплов с GIL:",tot,"из 1000 возможных за 5 с =>  GIL занят %.0f%% времени"%(tot/10))
    for c,v in cat.most_common(): print("  %5.1f%%  %s"%(100*v/tot,c))
    print("  топ функций:"); [print("     %5.1f%%  %s"%(100*v/tot,k[:90])) for k,v in leaf.most_common(6)]
