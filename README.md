# Jarkom-Modul-1-F07-202

### Soal 1 (Addressing)
#### Penyelesaian
Untuk menjawab soal ini, terdapat 2 pembagian kasus, dimana bagian pertama membahas tentang request aktivitas pengunggahan file untuk menjawab poin a dan b, sedangkan bagian kedua membahas tentang response terhadap aktivitas tersebut untuk menjawab poin c dan d.

Bagian Pertama : Pada display filter di file capture-nya (di dalam Wireshark), dapat memasukkan kueri sebagai berikut
```R
ftp contains "STOR"
```
Yang mana, melalui perintah "STOR" ini berarti melakukan pengunggahan file ke FTP server. Diperoleh hasil sebagai berikut

![SS Hasil Filter STOR](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/f3c997ba-a81d-474c-880f-1365a77ba5ee)

Berikutnya, dapat melakukan klik dua kali pada paket tersebut atau melihat pada jendela khusus yang menampilkan detail paketnya. Setelah itu, klik pada bagian `Transmission Control Protocol` untuk mendapatkan `sequence number (raw)` dan `acknowledgment number (raw)` pada proses request pengunggahan file-nya. Untuk lebih jelasnya, dapat dilihat pada gambar berikut.

![Seq Number dan Ack Number Request](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/d31b6057-5bcf-40f1-954f-2836bcb6db5c)

Adapun, untuk poin c dan d, kita perlu mencari paket data yang menjadi *response* dari permintaan paket sebelumnya. Paket data *response* ini bisa berada di bawahnya, atau dapat ditandai dengan adanya kesamaan nama file yang diunggah. Pada soal ini, file yang diunggah memiliki nama yaitu `c75-GrabThePisher.zip`, maka dapat dicari paket *response* yang terkait, seperti pada gambar berikut.

![GrabThePhiser Request dan Response](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/d1b322c7-5347-4875-9dc4-615e01eb640d)

Pada paket *response* tersebut, dapat melakukan hal yang sama yaitu membuka detail paketnya dan melihat `sequence number (raw)` dan `acknowledgment number (raw)`-nya di bagian `Transmission Control Protocol`. Dapat dilihat pada gambar berikut.

![Seq Number dan Ack Number Response](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/81b565f3-6e93-48ba-8b9d-f478412b4a4e)

### Soal 2 (Stream)
#### Penyelesaian
Untuk mencari web server seperti yang diminta soal, kita dapat melakukan `follow HTTP Stream` terhadap paket yang menggunakan protokol HTTP di dalam pcap file yang telah disediakan.

![http filtering](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/283d7cdd-55ca-40f9-a951-9479aab707b7)

![2 2 Web server http stream](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/e03a9f77-47bc-4235-b9e7-65a45f57f794)

Setelah itu akan tampak hasil stream-nya berisikan informasi termasuk web servernya, seperti pada gambar berikut.

![2 3 Web Server Found](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/fe409495-bb63-4639-bb8b-93771dea5472)

### Soal 4 (Addressing)
#### Penyelesaian
Untuk mencari nilai checksum dari suatu paket data, kita dapat melihat detail pada header paketnya. Pada soal, diminta untuk mencari pada paket nomor 130. Berikut isi detail paket 130 yang bersumber dari file pcap untuk nomor 4.

![4 1 Checksum in Packet 130's Detail](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/0b75e077-21b9-47f4-932a-801803010f56)

### Soal 7 (Filtering)
#### Penyelesaian
Untuk mengetahui jumlah paket yang menuju ke IP 184.87.193.88, kita dapat menuliskan kueri berikut pada display filter
```R
ip.dst == 184.87.193.88
```
Diperoleh hasil sebagai berikut. Dapat dilihat terdapat 6 paket dari hasil filtering.

![7 1 Number Of Packets](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/092f3746-bd92-4574-96e2-25a206eab3b8)

![7 2 Support for No7](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/48596171-2049-4faf-8f0f-368aad9b3bce)

### Soal 8 (Filtering)
#### Penyelesaian
Untuk hanya mengambil semua protokol paket yang menuju port 80 dan jika terdapat lebih dari 1 port, maka diambil berdasarkan urutan abjad, kita dapat menggunakan kueri sebagai berikut.
```R
tcp.dstport == 80 || udp.dstport == 80
```
Dengan begini kita akan mendapatkan paket-paket dengan protokol yang menuju port 80, seperti pada gambar berikut.

![8 1 To Port 80 Protocols](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/ca5a7a0a-3712-444f-bda1-2cb83dd7f61e)

### Soal 10 (Stream)
#### Penyelesaian
Untuk mencari kredensial ini, kita dapat melakukan `follow TCP Stream` pada paket-paket dengan protokol TELNET. Setelah itu melakukan pindah antar stream untuk menemukan kredensial yang tepat (Untuk soal ini, kami melakukan pendekatan uji coba tiap stream). Diperoleh hasil berikut pada perpindahan stream ke-3.

![10 1 Credential from Stream](https://github.com/rafifiaan/Jarkom-Modul-1-F07-2023/assets/108170236/137dfcb5-87ae-44c0-b584-6f769f1c03ed)

diperoleh kredensial dalam format `[username]:[password]` yaitu `dhafin:kesayangannyak0k0`
