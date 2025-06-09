from datetime import datetime
import sys
import platform
import signal
import os
import traceback

# Globalne varijable
HOME_DIR = os.path.expanduser("~")
LOG_FILE = os.path.join(HOME_DIR, "zapis.txt")

class SignalController():
    def sendSignal(signum):
        """
        Metoda koja šalje signal trenutnom procesu (python interpreteru)
        
        Args:
            signum (int): Signal koji treba poslati.
        """
        
        pid = os.getpid()
        try:
            os.kill(pid, signum)
        except OSError as e:
            print(f"Ne mogu poslati signal {signum}: {e}")
    
    def setSignals():
        """
        Metoda koja postavlja ponašanje procesa kada primi određeni signal
        """
        
        # Signali koji rezultiraju terminacijom procesa (ignoriramo ih)
        for s in [1,2,4,8,9,11,13,14,15,10,12]: 
            try:
                signal.signal(s, signal.SIG_IGN)
            except (OSError, RuntimeError, ValueError):
                # Neki signali se ne mogu ignorirati ili nisu podržani
                print(f"Postavljanje signala {s} neuspješno")

        # Za signale 3 i 6 postavi poseban handler
        for s in [3, 6]:
            try:
                signal.signal(s, specialSignalHandler)
            except (OSError, RuntimeError, ValueError):
                # Neki signali se ne mogu ignorirati ili nisu podržani
                print(f"Postavljanje signala {s} neuspješno")
            



def specialSignalHandler(signum, frame):
    """
    Funkcija koja se koristi kao callback kako bi definirali ponašanje procesa pri primanju signala 3 i 6.
    Ispisuje broj zaprimljenog signala, PID i PPID procesa, te zapisuje stanje stoga u datoteku zapis.txt

    Args:
        signum (int): Broj zaprimljenog signala.
        signum (frame obj): Okvir stoga u trenutku zaprimanja signala.
    """
    print(f"Zaprimljen signal broj {signum}")
    print(f"PID: {os.getpid()}, PPID: {os.getppid()}")
    with open(LOG_FILE, "a") as f:
        f.write(f"PID: {os.getpid()}, PPID: {os.getppid()}\n")
        f.write("Stack trace:\n")
        traceback.print_stack(file=f)
        f.write("\n")
    print(f"Informacije su zapisane u {LOG_FILE}")


def getMenuText():
    """
    Funkcija za ispis izbornika
    """
    print("-"*50)
    print("1. Prvi zadatak")
    print("2. Pošalji signal trenutnom procesu")
    print("3. Treći zadatak")
    print("4. Četvrti zadatak")
    print("'exit'/'out' - Završetak izvođenja programa")
    print("-"*50)


def getSystemInfo():
    """
    Funkcija koja ispisuje podatke o trenutnom vremenu, verziji python interpretera te operacijskog sustava
    """
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


def sendSignalToCurrentProcess():
    '''
    ==========
    2. Zadatak
    ==========
    Funkcija koja traži unos signala koji će se poslati trenutnom procesu , te ga šalje koristeći metodu sendSignal()
    '''
    while True:
        try:
            broj_signala = int(input("Unesite broj signala (1-31): "))
            if 1 <= broj_signala <= 31:
                break
            else:
                print("Pogrešan unos, unesite broj između 1 i 31.")
        except ValueError:
            print("Pogrešan unos, unesite cijeli broj.")
            
    SignalController.sendSignal(broj_signala)



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
    SignalController.setSignals() # Postavlja ponašanje procesa kada primi određene signale
    getSystemInfo()
    getMenuText()
    while True:

        menuChoice = input("Koju obradu želite pokrenuti: ")
        
        if (menuChoice == '1'):
            zadatakPrvi()
            getMenuText()
        elif (menuChoice == '2'):
            sendSignalToCurrentProcess()
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
        


if __name__ == "__main__":
    print("Ovo je seminarski rad tima 7. Dobrodošli!")
    menu()
    print("Dovidenja")
