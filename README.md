# TcpStego
Демонстрационная программа для скрытой передачи данных через поля заголовков TCP/IP

Программа разработана для тестирования возможности скрытой передачи данных. Для скрытой передачи были использованы служебные поля TCP и IPv4 протокола.

На стороне отправителя открытый текст шифруется по алгоритму AES. Шифртекст разбивается на блоки данных по 8 байт. После этого полю Type of Service заголовка IP присваивается значение 0 и объем зашифрованных данных в байтах помещается в поле идентификатора заголовка первого IP пакета, первые 8 байт информации помещаются в качестве значения опции Timestamp в поле options заголовка TCP.
Далее используется следующая структура для скрытой передачи данных:
-	Поле ID заголовка IP отводится под номер очередного блока (8 байт) зашифрованной информации. Данная идентификация позволяет корректно собирать информацию в том порядке, в котором ее отправили;
-	полю Type of Service заголовка IP присваивается значение 1;
-	8 байт информации помещаются в поле options заголовка TCP.

Для идентификации начала и конца сеанса связи между отправителем и получателем является флаг SYN и FIN в заголовке TCP пакета.
Данные передаются на заранее определенный TCP порт. На каждый пакет приемная сторона оповещает отправителя о том, что можно передавать следующий блок данных, отправляя в ответ ACK пакет. Это сделано с целью имитации нормального TCP соединения между клиентом и сервером.

Для каждого сообщения устанавливается новое TCP соединение. Каждое новое соединение открывается и закрывается корректно, поэтому не вызывает предупреждений при анализе трафика в Wireshark.

https://user-images.githubusercontent.com/88583217/195650704-4b0ee618-d2a2-4032-b96e-ccaf3b6bc935.mp4
