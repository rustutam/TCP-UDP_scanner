# TCP-UDP_scanner
Автор: Асбапов Рустам Русланович

Группа: КН-202

## Описание
Сканер TCP-UDP - консольная утилита, разработанная для сканирования TCP и UDP портов на хосте. Утилита способна определить протокол, который работает на открытом порту, такие как HTTP, SMTP, POP3, SNTP и другие.
Принцип работы TCP-UDP сканера основан на итеративном сканировании портов на удаленном хосте с целью определения открытых портов и протоколов, используемых на этих портах.

## Принцип работы
Сканер TCP-UDP использует сокеты для установления соединений с портами на указанном хосте и проверки их доступности. Для сканирования TCP портов применяется подход с установлением соединения, а для сканирования UDP портов используется отправка и прием пакетов данных.

Эта утилита позволяет сканировать заданный диапазон портов на указанном хосте и выводить информацию о доступности портов и определенном на них протоколе.

Благодаря параллельной обработке, сканер TCP-UDP обеспечивает эффективное сканирование портов и быструю выдачу результатов сканирования.

## Применение

Для получения справки используйте -h или --help:

``python main.py -h``

### Справка:
![image](https://github.com/rustutam/TCP-UDP_scanner/assets/113977718/b7d9e64c-d209-4a61-9ced-e6d3ae7d46fc)

## Пример работы

![image](https://github.com/rustutam/TCP-UDP_scanner/assets/113977718/2c4505dd-f480-4254-a310-bf20fb8cc406)


![image](https://github.com/rustutam/TCP-UDP_scanner/assets/113977718/936e665b-d432-4f12-8e6c-e08e1cafdcb0)

![image](https://github.com/rustutam/TCP-UDP_scanner/assets/113977718/ab9d1843-afb1-48e7-8f1a-bd28a89770f2)




