# Иконка KnotHop: варианты и встраивание

Черновик иконки Android-приложения. Все файлы генерирует `tools/gen.py` из одной геометрии.
Пересборка: `python3 design/icon/tools/gen.py` (нужны Pillow и `rsvg-convert`, сети не нужно).

## Варианты

Холст 108×108, фон `#0D2538` (одинаков для светлой и тёмной темы), линия `#F4F7FA`,
старт/выход и центральный узел `#34D399`. Линия 7 единиц, на 48 px это около 3 px.

- **A · Крендель** (`variant-a.svg`): классический силуэт. Широкая петля сверху,
  хвосты скрещены под ней. Старт и выход внизу, один промежуточный узел на вершине.
  Ближе всего к слову «крендель», но в 48 px хвосты сливаются в две точки.
- **B · Узел одной линией** (`variant-b.svg`): проекция трилистника, одна непрерывная линия.
  Разрывы у перекрёстков — это «прыжки». Концы линии выделены как старт и выход,
  два промежуточных узла. Честный узел, но в 48 px это почти пятно.
- **C · Восьмёрка** (`variant-c.svg`): петля-восьмёрка с тремя точками. Старт слева,
  выход справа, хаб-узел в перекрёстке. Единственный вариант, который в 48 px и в
  монохроме читается однозначно.

## Рекомендация: C

Силуэт C проще всего узнать в маленьком размере и в монохроме, и он отражает суть
маршрутизации: путь от старта через хаб к выходу. Минус: это не буквальный крендель.
Если владелец хочет именно крендель, выбирайте A: в `gen.py` замените
`RECOMMENDED = "c"` на `"a"` и пересоберите.

## Проверки

- Безопасная зона adaptive icon (диаметр 66 по центру): наибольший радиус у всех трёх
  вариантов не выше 32.2 единицы при пределе 33 (`gen.py` падает, если предел превышен).
- Превью `preview-sheet.png`: каждый вариант в 512, 192, 48 px (светлый и тёмный фон),
  круглая маска 192 px и монохром 192/48 px.
- Перекрёстки B проверены: 3 перекрёстка, чередование over/under сходится, кусков 4.
- VectorDrawable: все XML разбираются, пути `ic_launcher_foreground.xml` совпадают с
  путями `variant-c.svg` побайтно.
- **Не проверено на устройстве**: Android SDK здесь нет, поэтому VectorDrawable не
  рендерился через Android. Рендер в launcher и тема Android 13 требуют проверки на
  телефоне.

## Файлы

- `variant-a.svg`, `variant-b.svg`, `variant-c.svg`: полные иконки (фон + передний план).
- `preview-sheet.png`: все варианты рядом.
- `previews/`: PNG каждого варианта: 512, 192, 48, круг 192, монохром 192 и 48.
- `android-res/`: ресурсы для рекомендованного варианта (C):
  - `drawable/ic_launcher_foreground.xml`: передний план, VectorDrawable из SVG.
  - `drawable/ic_launcher_background.xml`: фон, сплошной `#0D2538`.
  - `drawable/ic_launcher_monochrome.xml`: монохром для Android 13+ (чёрный, Android берёт альфа-канал).
  - `mipmap-anydpi-v26/ic_launcher.xml` и `ic_launcher_round.xml`: adaptive-icon.
  - `mipmap-{mdpi,hdpi,xhdpi,xxhdpi,xxxhdpi}/ic_launcher.png` и `ic_launcher_round.png`:
    legacy PNG 48/72/96/144/192. Нужны только для устройств без adaptive-icon. В
    проекте `minSdkVersion="26"`, поэтому их можно не копировать.
- `tools/gen.py`: генератор.

## Встраивание (ничего не скопировано)

Сейчас в `bench/android/vpn/` нет `res/` и нет `android:icon` в манифесте.

1. Скопировать в `bench/android/vpn/res/`:
   - `android-res/drawable/*.xml` → `bench/android/vpn/res/drawable/`
   - `android-res/mipmap-anydpi-v26/*.xml` → `bench/android/vpn/res/mipmap-anydpi-v26/`
   - при необходимости `android-res/mipmap-<плотность>/*.png` → `bench/android/vpn/res/mipmap-<плотность>/`
     (каталоги создаются при копировании).
2. В `bench/android/vpn/AndroidManifest.xml` в элемент `<application ...>` добавить атрибуты:
   `android:icon="@mipmap/ic_launcher" android:roundIcon="@mipmap/ic_launcher_round"`.
3. В `bench/android/build.sh` сейчас `aapt2 link` вызывается без скомпилированных
   ресурсов, поэтому иконка в APK не попадёт. Нужен шаг компиляции перед линковкой, например:
   ```sh
   "$BT/aapt2" compile --dir "$SRC/res" -o "$W/res.zip"
   "$BT/aapt2" link -o "$W/base.apk" -I "$PLATFORM" --manifest "$SRC/AndroidManifest.xml" \
       "$W/res.zip" --min-sdk-version $API --target-sdk-version 34
   ```
   Шаг нужен только для `vpn`; `build.sh` не менялся, это решение владельца.
4. Проверка после сборки: `aapt2 dump badging base.apk | grep -i icon` должен показать
   иконку приложения, и она должна появиться на экране телефона.

Метка приложения в манифесте по-прежнему `android:label="rawg VPN"`. Это не часть задачи
иконки и не менялось.
