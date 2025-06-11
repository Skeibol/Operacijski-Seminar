from datetime import datetime
import sys
import platform
import signal
import os
import traceback
import threading
import time
try:
    import pwd
except:
    print("Modul pwd nije dostupan na platformi Windows")

# Globalne varijable
HOME_DIR = os.path.expanduser("~")
LOG_FILE = os.path.join(HOME_DIR, "zapis.txt")
OPERATING_SYSTEM = ""

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
        for s in [1,2,3,9,15,17,19]: 
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
        frame (frame obj): Okvir stoga u trenutku zaprimanja signala.
    """
    print(f"Zaprimljen signal broj {signum}")
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
    
    Returns:
        str: Verzija operacijskog sustava radi kontrole toka programa (izbjegavanje greški sa raznim funkcijama)
    """
    currentTime = datetime.now()
    print(f"{currentTime.strftime('%H:%M:%S %A %d-%m-%Y')}")
    pythonVersion = sys.version_info
    print(f"Verzija pythona : {pythonVersion[0]}.{pythonVersion[1]}")
    operatingSystem = platform.platform()
    print(f"Verzija operacijskog sustava : {operatingSystem}")
    
    return operatingSystem[0] == "W"



def unos_broja(min_vrijednost=1, max_vrijednost=10):
    """
    Traži od korisnika unos pozitivnog cijelog broja unutar zadanog intervala.

    Argumenti:
    min_vrijednost (int): donja granica intervala (uključivo)
    max_vrijednost (int): gornja granica intervala (uključivo)

    Povratna vrijednost:
    int: uneseni broj koji zadovoljava uvjete

    Izuzeci:
    Ignorira neispravne unose i traži ponovni unos dok se ne unese ispravna vrijednost.
    """
    while True:
        try:
            n = int(input(f"Unesi pozitivnu cjelobrojnu vrijednost u intervalu [{min_vrijednost},{max_vrijednost}]: "))
            if min_vrijednost <= n <= max_vrijednost:
                return n
            else:
                print(f"Pogrešan unos. Broj mora biti u intervalu [{min_vrijednost},{max_vrijednost}].")
        except ValueError:
            print("Pogrešan unos. Unesi cijeli broj.")


def dohvati_pid_djede(pid_roditelj):
    """
    Dohvaća PID djeda procesa (roditelja roditelja) čitajući /proc/[pid_roditelj]/status.

    Argumenti:
    pid_roditelj (int): PID roditeljskog procesa

    Povratna vrijednost:
    int ili None: PID djeda ako postoji, inače None
    """
    try:
        with open(f"/proc/{pid_roditelj}/status", "r") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except FileNotFoundError:
        # Datoteka ne postoji, npr. proces je završio ili nema pristupa
        return None


def dohvati_podatke_o_procesu(pid):
    """
    Dohvaća korisničko ime vlasnika procesa i njegov prioritet.

    Argumenti:
    pid (int): PID procesa

    Povratna vrijednost:
    tuple: (pid, korisničko_ime, prioritet)
    ili None ako nije moguće dohvatiti podatke
    """
    try:
        uid = os.stat(f"/proc/{pid}").st_uid  # Dohvaća UID vlasnika procesa
        user = pwd.getpwuid(uid).pw_name  # Dohvaća korisničko ime prema UID-u
        prio = os.getpriority(os.PRIO_PROCESS, pid)  # Dohvaća prioritet procesa
        return (pid, user, prio)
    except Exception:
        # Ako podaci nisu dostupni (proces je završio ili nema dozvolu), ignoriramo
        return None


def forkChildProcesses():
    """
    Glavna funkcija programa koja:
    - traži od korisnika broj n
    - stvara dječji proces pomoću os.fork()
    - u dječjem procesu ispisuje PID, korisnika i prioritet procesa: sebe, roditelja i djeda
    - aktivno čeka n sekundi (koristeći time.sleep da se izbjegne zauzeće CPU)
    - roditelj čeka završetak dječjeg procesa
    """
    n = unos_broja()

    pid = os.fork()

    if pid == 0:
        # Dječji proces
        os.chdir(HOME_DIR)  # Promijeni radni direktorij na home direktorij korisnika

        pid_djete = os.getpid()
        pid_roditelj = os.getppid()
        pid_djede = dohvati_pid_djede(pid_roditelj)

        procesi = []
        for pid_provjera in [pid_djete, pid_roditelj, pid_djede]:
            if pid_provjera is not None:
                podaci = dohvati_podatke_o_procesu(pid_provjera)
                if podaci is not None:
                    procesi.append(podaci)

        procesi.sort(key=lambda x: x[0])  # Sortiraj po PID-u radi preglednosti

        print("PID\tKorisnik\tPrioritet")
        for pid_info, korisnik, prioritet in procesi:
            print(f"{pid_info}\t{korisnik}\t{prioritet}")

        time.sleep(n)  # Pauza n sekundi, bez zauzeća CPU-a

        os._exit(0)  # Završetak dječjeg procesa bez pokretanja čišćenja interpreterom

    else:
        # Roditeljski proces čeka da dijete završi
        os.waitpid(pid, 0)
        print("Podproces završen. Povratak u glavni izbornik.")


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



def interval(m):
    """
    Dijeli interval [1, m] na tri približno jednake cjeline.

    Argumenti:

    m -- pozitivni cijeli broj veći od 6 milijuna, određuje gornju granicu 
         intervala koji se dijeli

    Vraća:

    Funkcija vraća trojku tupleova ((start1, kraj1), (start2, kraj2), (start3, kraj3)) 
    koji predstavljaju početne i krajnje vrijednosti za tri dijela intervala, 
    raspoređene tako da svaka dretva obrađuje približno jednaki broj elemenata.
    """
    velicina = m // 3
    start1 = 1
    kraj1 = velicina
    start2 = kraj1 + 1
    kraj2 = 2 * velicina
    start3 = kraj2 + 1
    kraj3 = m
    return (start1, kraj1), (start2, kraj2), (start3, kraj3)

def razlika_korijena(start, kraj, putanja, trenutni_semafor, sljedeci_semafor):
    """
    Izračunava razliku kvadratnih korijena svih cijelih brojeva u danom 
    intervalu i zapisuje međurezultate u datoteku. Koristi semafore za 
    sinkronizaciju pisanja u datoteku između dretvi.

    Argumenti:

    start -- početna vrijednost intervala, cijeli broj
    kraj -- krajnja vrijednost intervala, cijeli broj
    putanja -- putanja do datoteke u koju se zapisuju međurezultati, string
    trenutni_semafor -- semafor kojim dretva upravlja pristupom datoteci 
                        u svom trenutnom koraku
    sljedeci_semafor -- semafor koji se otključava kako bi sljedeća dretva 
                        mogla nastaviti s radom
    
    Vraća:
    
    Funkcija ne vraća vrijednost (None).
    """

    rezultat = 0
    rezultati_lista = []

    for i in range(start, kraj + 1):
        korijen = i ** 0.5
        if i == 1:
            rezultat += korijen
        else:
            rezultat -= korijen
        rezultati_lista.append(f"{i}: {rezultat:.4f}\n")

    trenutni_semafor.acquire()
    with open(putanja, "a") as f:
        f.writelines(rezultati_lista)
    sljedeci_semafor.release()

def threadingRootDifference():
    """
    Glavna funkcija koja upravlja unosom, raspodjelom rada među dretvama 
    i koordinacijom izračuna.

    Argumenti:

    Funkcija nema argumente.

    Vraća:

    Funkcija ne vraća vrijednost (None).
    """
    semafor1=threading.Semaphore(1)
    semafor2=threading.Semaphore(0)
    semafor3=threading.Semaphore(0)
    
    while True:
        try:
            m = int(input("Unesi pozitivni cijeli broj veći od 6 milijuna: "))
            if m > 6000000:
                break
            else:
                print("Pogrešan unos. Broj mora biti veći od 6 milijuna.")
        except ValueError:
            print("Pogrešan unos. Unos mora biti cijeli broj.")

    (s1, k1), (s2, k2), (s3, k3) = interval(m)
    kucni_dir_putanja = os.path.join(os.path.expanduser("~"), "meduvrijednosti.txt")

    open(kucni_dir_putanja, "w").close()  # očisti datoteku

    t1 = threading.Thread(target=razlika_korijena, args=(s1, k1, kucni_dir_putanja,semafor1,semafor2))
    t2 = threading.Thread(target=razlika_korijena, args=(s2, k2, kucni_dir_putanja,semafor2,semafor3))
    t3 = threading.Thread(target=razlika_korijena, args=(s3, k3, kucni_dir_putanja,semafor3,threading.Semaphore(0)))

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()

    print("\nRezultati su zapisani u datoteku.\n")
    
all_divisors = []
divisors_lock = threading.Lock()
first_two_threads_done = threading.Event()

def findDivisors(start, end, thread_name):
    """
    Funkcija za pronalaženje djelitelja brojeva unutar zadanog raspona.
    """
    print(f"[{thread_name}] Početak izvođenja.")
    localDivisors = []
    for num in range(start, end + 1):
        for i in range(1, num + 1):
            if num % i == 0:
                localDivisors.append(i)
    
    with divisors_lock:
        all_divisors.extend(localDivisors)
    print(f"[{thread_name}] Kraj izvođenja.")


def processEvenDivisors(thread_name):
    """
    Funkcija koja pronalazi sve parne djelitelje iz globalne liste, uklanja duplikate,
    sortira ih i ispisuje.
    """
    print(f"[{thread_name}] Početak izvođenja.")
    startTime = time.time()
    
    # Čeka dok prve dvije dretve ne završe s radom
    first_two_threads_done.wait()

    uniqueEvenDivisors = set() # Koristimo set za automatsko uklanjanje duplikata

    with divisors_lock: # Zaključava listu prije čitanja
        # Pronađi sve parne djelitelje i dodaj ih u set (set automatski rješava duplikate)
        for divisor in all_divisors:
            if divisor % 2 == 0:
                uniqueEvenDivisors.add(divisor)
        
    # Pretvori set natrag u listu i sortiraj je
    sorted_uniqueEvenDivisors = sorted(list(uniqueEvenDivisors))

    print("\nSvi parni djelitelji (sortirani i bez ponavljanja):")
    print(sorted_uniqueEvenDivisors)
    
    endTime = time.time()
    executionTime = endTime - startTime
    print(f"[{thread_name}] Kraj izvođenja.")
    print(f"[{thread_name}] Vrijeme trajanja izvođenja: {executionTime:.2f} sekundi.")

def threadingDivision():
    all_divisors = [] # Resetiraj listu za svaki poziv funkcije
    first_two_threads_done.clear() # Resetiraj Event

    while True:
        try:
            k = int(input("Unesite pozitivnu cjelobrojnu vrijednost k (1000 - 200000): "))
            if 1000 <= k <= 200000:
                break
            else:
                print("Vrijednost k mora biti između 1000 i 200000.")
        except ValueError:
            print("Pogrešan unos. Unesite cijeli broj.")

    # Podjela intervala na dvije dretve
    midpoint = k // 2
    
    # Kreiranje dretvi
    thread1 = threading.Thread(target=findDivisors, args = (1, midpoint, "Thread-1"))
    thread2 = threading.Thread(target=findDivisors, args = (midpoint + 1, k, "Thread-2"))
    thread3 = threading.Thread(target=processEvenDivisors, args = ("Thread-3",))

    # Pokretanje dretvi
    thread1.start()
    thread2.start()
    thread3.start()

    # Čekanje da prve dvije dretve završe
    thread1.join()
    thread2.join()
    
    # Signaliziraj trećoj dretvi da su prve dvije završile
    first_two_threads_done.set()

    # Čekanje da treća dretva završi
    thread3.join()
    print("\nSve dretve su završile izvođenje.")


def menu():
    SignalController.setSignals() # Postavlja ponašanje procesa kada primi određene signale
  
    
    if(getSystemInfo()): # Ako se program pokreće na platformi windows, zaustavimo izvođenje u ovom trenutku (Windows ne podržava većinu metodi koje se koriste)
        print("Neke funkcionalnosti nisu dostupne na platformi Windows.")
        return
    else:
        getMenuText()
    
    while True:

        menuChoice = input("Koju obradu želite pokrenuti: ")
        
        if (menuChoice == '1'):
            forkChildProcesses()
            getMenuText()
        elif (menuChoice == '2'):
            sendSignalToCurrentProcess()
            getMenuText()
        elif (menuChoice == '3'):
            threadingRootDifference()
            getMenuText()
        elif (menuChoice == '4'):
            threadingDivision()
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
