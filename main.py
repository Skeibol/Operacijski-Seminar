from datetime import datetime
import sys
import platform


def getMenuText():
    print("1. Opis prve..")
    print("2. Opis dsadadd..")
    print("3. Opis prEeqewqewqqwqw..")
    print("4. ....1321ewq..")
    print("'exit'/'out' - Završetak izvođenja programa")
    print("-"*50)


def getSystemInfo():
    currentTime = datetime.now()
    print(f"{currentTime.strftime('%H:%M:%S %A %d-%m-%Y')}")
    pythonVersion = sys.version_info
    print(f"Verzija pythona : {pythonVersion[0]}.{pythonVersion[1]}")
    operatingSystem = platform.platform()
    print(f"Verzija operacijskog sustava : {operatingSystem}")


def zadatakPrvi():
    '''
    Od korisnika se traži dodatan unos pozitivne cjelobrojne vrijednosti n (uz
    odgovarajuću poruku na zaslonu), ne veće od 10 (potrebno napraviti provjeru). Ako korisnik
    nije unio valjanu vrijednost, nudi se ponavljanje unosa cjelobrojne vrijednosti. Ako je korisnik
    unio valjanu vrijednost, pokreće se novi proces koji najprije postavlja korisnikov kućni direktorij
    kao radni direktorij, a zatim na zaslon ispisuje sljedeće podatke: PID, stvarni korisnički ID
    vlasnika te vrijednost prioriteta i to za trenutni podproces koji se izvodi, za njegovog roditelja,
    te za roditelja od roditelja (dakle, za sveukupno 3 procesa). Pritom je potrebno provjeriti
    postoji li toliko procesa, te ako ne, obavijestiti korisnika o tome. Ispis podataka o procesima na
    zaslonu treba biti u tabličnome obliku (vrijednosti odvojiti tabulatorom, napraviti
    odgovarajuće zaglavlje tablice), počevši od procesa s najmanjim PID-om, a zapis o svakome
    procesu treba se nalaziti u svome retku. Npr.

    PID Korisnik Prioritet
    1010 student 20
    1123 student 20
    1234 student 25

    Podproces se izvodi n sekundi nakon čega se ponovo počinje izvoditi glavni proces koji
    prikazuje glavni izbornik. Glavni proces treba čekati na završetak podprocesa, pa onda završiti
    izvođenje funkcionalnosti i prikazati glavni izbornik (Napomena: nije dozvoljeno reguliranje
    trajanja podprocesa funkcijom sleep() niti signalom.)
    '''
    pass


def zadatakDrugi():
    '''
    Omogućava korisniku unos broja signala koji će se poslati trenutnome
    procesu (interpretoru naredbi). Trenutni proces ignorira sve signale čiji su brojevi u rasponu
    od 1 do 20 a rezultiraju zaustavljanjem procesa u izvođenju (samostalnim istraživanjem pronaći
    popis akcija kojima rezultiraju pojedini signali). Sve ostale signale program obrađuje kako je
    zadano (engl. default), uz definiciju odgovarajućih upravljača. Ako je broj signala veći od 31,
    javlja se poruka o pogrešnom unosu i upit za unos se ponavlja sve dok se ne unese korektna
    vrijednost. Za zaprimljeni signal broj 3 ili 6, program na zaslon ispisuje poruku o zaprimljenom
    signalu i njegovu rednu broju, zapisuje PPID i PID procesa, te trenutno stanje stoga u datoteku
    zapis.txt koja se stvara u kućnom direktoriju korisnika, obavještava korisnika porukom o
    tome što je napravio, pa nastavlja uobičajeno izvođenje (prikaz glavnoga izbornika).
    '''

    pass


def zadatakTreci():
    '''
    Korisniku se omogućava unos pozitivne cjelobrojne vrijednosti m veće od
    6 milijuna (potrebno je napraviti provjeru unosa vrijednosti i ponuditi ponovni unos ako je
    vrijednost manja od tražene). Kada korisnik unese valjanu vrijednost, počinje proračun razlike
    drugih korijena svih vrijednosti iz intervala [1,m] (tj., √1 −√2 − ⋯ −√𝑚) u tri dretve. Podjelu
    intervala proračuna po dretvama potrebno je učiniti tako da svaka dretva vrši proračun
    otprilike jednake veličine intervala. Međuvrijednosti proračuna potrebno je zapisati u datoteku
    meduvrijednosti.txt koja će se stvoriti u kućnom direktoriju korisnika i to u obliku
    broj: trenutni_rezultat_oduzimanja, jedan ispod drugoga za svaki par vrijednosti,
    npr.
    1: 1
    2: -0.4142
    3: -2.1463
    …
    (Napomena: višedretveni pristup obvezni ste sinkronizirati primjenom semafora.)
    '''

    pass


def zadatakCetvrti():
    '''
    Korisniku se omogućava unos pozitivne cjelobrojne vrijednosti k, ne manje
    od 1 000 ni veće od 200 000 (potrebno napraviti provjeru unosa i ponuditi ponovni unos ako
    vrijednost ne odgovara intervalu). Program se izvršava u tri dretve od kojih prve dvije najprije
    rade listu dividers koja sadrži sve djelitelje svakog broja iz intervala od [1,k] (interval
    proračuna ravnomjerno rasporediti na dvije dretve), a po njihovu završetku treća dretva zatim
    stvara novu listu koja sadrži samo parne brojeve iz prethodne liste i ispisuje ju na zaslonu.
    Svaka dretva na početku i na kraju izvođenja mora na zaslonu ispisati vlastiti naziv koji joj
    dodjeljuje sustav (npr. Thread-1), uz odgovarajuću obavijest o početku ili završetku
    izvođenja, dok dodatno treća dretva na zaslon ispisuje i vrijeme trajanja vlastitog izvođenja u
    seknudama. (Napomena: pri implementaciji je potrebno koristiti odgovarajući mehanizam za
    vremensko usklađivanje višedretvenoga rada.)
    '''

    pass


def menu():
    getSystemInfo()
    getMenuText()
    while True:

        menuChoice = input("Koju obradu želite pokrenuti: ")
        
        if (menuChoice == '1'):
            zadatakPrvi()
            getMenuText()
        elif (menuChoice == '2'):
            zadatakDrugi()
            getMenuText()
        elif (menuChoice == '3'):
            zadatakTreci()
            getMenuText()
        elif (menuChoice == '4'):
            zadatakCetvrti()
            getMenuText()
        elif (menuChoice == 'out' or menuChoice == 'exit'):
            break
        elif (menuChoice == ''):
            # Samo enter / ne prikazuje se izbornik niti nista
            pass
        else:
            print(f"Unos '{menuChoice}' nije prepoznat, pokušajte ponovo")
        print("-"*50)


if __name__ == "__main__":
    print("Ovo je seminarski rad tima ?. Dobrodošli!")
    menu()
    print("Dovidenja")
