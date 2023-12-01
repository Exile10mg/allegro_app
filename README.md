# AllegroApp - Automatyzacja Działań na Allegro

## Opis Programu

AllegroApp to zaawansowane narzędzie stworzone do automatyzacji różnych działań na platformie Allegro. Program został zaimplementowany w języku Python przy użyciu interfejsu graficznego Tkinter. Pozwala użytkownikowi na wygodne zarządzanie kontem Allegro, wysyłanie wiadomości do wielu wątków, analizę cen, a także eksportowanie danych do plików Excel.

## Funkcje Programu

### 1. Logowanie i Weryfikacja Użytkownika

AllegroApp umożliwia logowanie się do konta Allegro poprzez stronę logowania Allegro. W przypadku pierwszego uruchomienia programu lub wygaśnięcia tokenu dostępu, program przeprowadzi proces weryfikacji użytkownika. W tym celu otworzy stronę logowania Allegro, gdzie użytkownik będzie musiał wprowadzić kod autoryzacyjny.

### 2. Pobieranie Informacji o Koncie

Program umożliwia pobieranie szczegółowych informacji o koncie Allegro. Zwracane informacje obejmują ID konta, nazwę użytkownika, imię, nazwisko, adres e-mail, bazę rynku, firmę i funkcje związane z kontem.

### 3. Wysyłanie Wiadomości do Wszystkich Wątków

AllegroApp pozwala na efektywne wysyłanie jednej wiadomości do wszystkich aktywnych wątków na platformie Allegro. Użytkownik wprowadza treść wiadomości, a program automatycznie przesyła ją do każdego wątku.

### 4. Wysyłanie Automatycznych Wiadomości

Jedną z unikalnych funkcji AllegroApp jest możliwość ustawiania automatycznych wiadomości w zależności od różnych scenariuszy. Użytkownik może skonfigurować program do wysyłania wiadomości w określonych sytuacjach, na przykład po zakończeniu aukcji, zmianie statusu zamówienia, itp.

### 5. Zapisywanie Aktywnych Ofert do Pliku Excel

Program oferuje funkcję zapisywania informacji o aktywnych ofertach do pliku Excel. Zapisywane są istotne dane, takie jak tytuł oferty i dostępna liczba sztuk.

### 6. Sprawdzanie Salda Konta

AllegroApp umożliwia szybkie sprawdzanie salda konta na platformie Allegro. To przydatne narzędzie do monitorowania finansów z poziomu jednego interfejsu.

### 7. Analiza Cen na Podstawie Frazy

Program przeprowadza analizę cen na podstawie wprowadzonych fraz. Użytkownik podaje frazy, a AllegroApp wyświetla wyniki analizy, takie jak najwyższa cena, najniższa cena, średnia cena i ilość aukcji dla każdej z fraz.

### 8. Eksport Wyników Analizy do Pliku Excel

AllegroApp umożliwia eksport wszystkich wyników analizy do jednego pliku Excel. Dzięki temu użytkownik może łatwo przechowywać i udostępniać zebrane dane.

### 9. Pokazywanie Wiadomości

Program pozwala na wygodne przeglądanie wiadomości związanych z kontem Allegro. Użytkownik może łatwo sprawdzić historię komunikacji z innymi użytkownikami.

## Instrukcje Uruchomienia

1. Uruchom program, uruchamiając skrypt `allegro_app.py`.
2. W przypadku pierwszego uruchomienia lub wygaśnięcia tokenu dostępu, program przeprowadzi proces weryfikacji użytkownika. Otwórz stronę logowania Allegro, wprowadź kod autoryzacyjny, a następnie uzyskaj dostęp.

## Konfiguracja Automatycznych Wiadomości

Aby skonfigurować automatyczne wiadomości, użytkownik musi przejść do sekcji "Automatyczne Wiadomości" w interfejsie programu. Tam może zdefiniować różne scenariusze, określając warunki i treść wiadomości.

### Przykładowa Konfiguracja Automatycznych Wiadomości

1. **Po Zakończeniu Aukcji:** Ustaw program do automatycznego wysyłania podziękowań po zakończeniu każdej aukcji.
2. **Zmiana Statusu Zamówienia:** Skonfiguruj AllegroApp do automatycznego wysyłania informacji o zmianie statusu zamówienia do kupującego.

## Autor

AllegroApp został stworzony przez Mike Boro w 2023 roku.

## Wymagania Systemowe

- Python 3.6+
- Tkinter
- requests
- openpyxl
- pandas

## Instalacja Zależności

Aby zainstalować wszystkie niezbędne zależności, wykonaj poniższą komendę w terminalu:

```bash
pip install -r requirements.txt
```

## Uruchamianie Programu

Po zainstalowaniu zależności, uruchom program za pomocą poniższej komendy:

```bash
python allegro_app.py
```

## Licencja

Ten projekt jest objęty licencją MIT - szczegóły w pliku [LICENSE](LICENSE).

## Kontakt

W razie pytań lub uwag skontaktuj się z autorem:

- GitHub: [MikeBoro](https://github.com/MikeBoro)

**Ciesz się korzystaniem z AllegroApp!**
