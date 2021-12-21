# mitre-lib

Python Library for Mapping and Processing Incident Info with MITRE ATT&CK

## Зачем это нужно

Уже несколько лет, как даже самые простые с точки зрения расследования инциденты ИБ характеризуются достаточно богатым техническим арсеналом. Выявлять и расследовать инциденты только на основании индикаторов компрометации и сугубо технических деталей становится все сложнее. В таких условиях важным является анализ контекста и выработка тактик, техник и процедур (TTPs) на основе опыта специалиста. Однако опыт одного или даже команды аналитиков не может быть абсолютно полным и покрыть все известные случаи. К тому же, ручная обработка каждого инцидента, сопоставление TTPs и процесс аттрибуции занимают большое количество времени в цикле анализа. 

Разработанная библиотека позволяет:
1. Использовать признаный во всем мире стандарт описания инцидентов ИБ.
2. Объединить опыт расследований всего сообщества.
3. Использовать унифицированный интерфейс для описания и хранения информации об инцидентах.
4. Значительно ускорить процессы аттрибуции и сопоставления с базой знаний расследованных ранее инцидентов.

Разработанная библиотека **НЕ** позволяет:
1. Сделать всю работу за аналитика.
2. Исключить значение опыта аналитика.
3. Достоверно аттрибутировать инциденты на основании лишь индикаторов компрометации.
4. Автоматически обмениваться своими наработками.

## Общая информация

Представленная библиотека разработана на основе стандарта STIX 2.1 (Structured Threat Information Expression). Актуальную версию стандарта можно найти [здесь](https://docs.oasis-open.org/cti/stix/)

Перед использованием библиотеки _настоятельно рекомендуется_ ознакомится со [схемой объектов](#схема-объектов).

Каждый из описанных ниже объектов обладает своим набором свойств и типов связей. Подробнее можно ознакомится [здесь](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_nrhq5e9nylke) или в локальной html странице в репозитории.


## [Схема объектов](#scheme)

<table class="a" style="border-collapse:
 collapse;border:none" width="624" cellspacing="0" cellpadding="0" border="1">
 <tbody><tr>
  <td colspan="5" style="width:390.0pt;border:solid black 1.0pt;
  background:#073763;padding:5.0pt 5.0pt 5.0pt 5.0pt" width="520" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><b><span style="color:white" lang="EN">STIX Objects</span></b></p>
  </td>
  <td rowspan="3" style="width:78.0pt;border:solid black 1.0pt;
  border-left:none;background:#D9D9D9;padding:5.0pt 5.0pt 5.0pt 5.0pt" width="104" valign="top">
  <p class="MsoNormal"><span lang="EN">&nbsp;</span></p>
  <p class="MsoNormal"><span lang="EN">&nbsp;</span></p>
  <p class="MsoNormal"><span lang="EN">&nbsp;</span></p>
  <p class="MsoNormal" style="text-align:center" align="center"><span style="color:black" lang="EN">STIX Bundle Object</span></p>
  </td>
 </tr>
 <tr>
  <td colspan="3" style="width:3.25in;border:solid black 1.0pt;
  border-top:none;background:#CFE2F3;padding:5.0pt 5.0pt 5.0pt 5.0pt" width="312" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><b><span style="color:black" lang="EN">STIX Core Objects</span></b></p>
  </td>
  <td colspan="2" style="width:156.0pt;border-top:none;
  border-left:none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  background:#CFE2F3;padding:5.0pt 5.0pt 5.0pt 5.0pt" width="208" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><b><span style="color:black" lang="EN">STIX Meta Objects</span></b></p>
  </td>
 </tr>
 <tr>
  <td style="width:78.0pt;border:solid black 1.0pt;
  border-top:none;padding:5.0pt 5.0pt 5.0pt 5.0pt" width="104" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><span lang="EN">STIX Domain Objects <br>
  (SDO)</span></p>
  </td>
  <td style="width:78.0pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  padding:5.0pt 5.0pt 5.0pt 5.0pt" width="104" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><span lang="EN">STIX Cyber-observable Objects<br>
  (SCO)</span></p>
  </td>
  <td style="width:78.0pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  padding:5.0pt 5.0pt 5.0pt 5.0pt" width="104" valign="top">
  <p class="MsoNormal" style="text-align:center" align="center"><span lang="EN">STIX
  Relationship Objects<br>
  (SRO)</span></p>
  </td>
  <td style="width:78.0pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  padding:5.0pt 5.0pt 5.0pt 5.0pt" width="104" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><span lang="EN">Language Content Objects</span></p>
  </td>
  <td style="width:78.0pt;border-top:none;border-left:
  none;border-bottom:solid black 1.0pt;border-right:solid black 1.0pt;
  padding:5.0pt 5.0pt 5.0pt 5.0pt" width="104" valign="top">
  <p class="MsoNormal" style="text-align:center;border:none" align="center"><span lang="EN">Marking Definition Objects</span></p>
  </td>
 </tr>
</tbody></table>

__STIX Domain Objects__ - 
результаты анализа, которые представляют поведение и конструкции субъектов вредоносной активности, создаваемые специалистами при реагировании на инцидент.

__STIX Cyber-observable Objects__ - 
Технические детали, выявляемые при реагировании, позволяющие определить __STIX Domain Objects__. 
(тоже самое что **IOCs**)

__STIX Relationship Objects__ - объекты, позволяющие соединить различные объекты в граф, для более полного понимания инцидента.

__STIX Meta Objects__ - вспомогательные объекты, позволяющие повысить уровень восприятия и поддерживать рабочие процессы.

__STIX Bundle Object__ - главный объект, объединяющий все объекты STIX.

### Stix Domain Objects:
 - **Шаблон атаки**: набор TTPs, который описывает способы, которыми злоумышленники пытаются скомпрометировать цели (__Attack Pattern__)
 - **Кампания**: это группа враждебных действий, которая описывает набор злонамеренных действий или атак, которые происходят в течение определенного периода времени против определенного набора целей (__Campaign__)
 - **Превентивные меры**: это действия, предпринимаемые либо для предотвращения атаки, либо в ответ на уже начавшуюся атаку (__Course of action__)
 - **Группа объектов**: позволяет объединить все объекты, имеющие общий контекст, в одну группу (__Grouping__)
 - **Идентификатор**: может представлять реальных людей, организации или группы (например, Сбер), а также классы лиц, организации, системы или группы (например, финансовый сектор) (__Identity__)
 - **Инцидент**: в настоящей версии стандарта объект-заглушка, позволяющий лишь ввести общее описание инцидента (__Incident__)
 - **Индикатор**: шаблон, позволяющий создать индикатор вредоносной активности любого типа для другого объекта (__Indicator__)
 - **Инфраструктура**: объект описывает любую сущность (ИС, ПО, сервис, физический или виртуальный ресурс), предназначенную для поддержания вредоносной активности (кроме того является типом TTPs). (__Infrastructure__)
 - **Набор вторжений**: сгрупированный набор вредносных воздействий и ресурсов с общими свойствами, которые, как считается, организуются одной группировкой. (__Intrusion Set__)
 - **Местоположение**: представляет собой географическое положение любого объекта. (__Location__)
 - **ВПО**: характеризует, идентифицирует и классифицирует экземпляры и семейства вредоносных программ на основе данных, которые могут быть получены в результате анализа. (__Malware__)
 - **Анализ ВПО**: фиксирует метаданные и результаты определенного статического или динамического анализа, выполненного на экземпляре или семействе вредоносных программ. (__Malware Analysis__)
 - **Примечание**: предназначено для передачи информативного текста для предоставления дальнейшего контекста и / или для обеспечения дополнительного анализа, не содержащегося в объектах STIX, к которым относится примечание. (__Note__)
 - **Наблюдаемые данные**: содержат информацию о связанных с инцидентом объектах, таких как файлы, системы и сети, с использованием объектов SCO. (__Observed Data__)
 - **Оценка**: субъектвный взгляд на правильность информации в объекте STIX. (__Opinion__)
 - **Отчеты**: наборы аналитических данных об угрозах, сфокусированные на одной или нескольких темах, таких как описание субъекта угрозы, вредоносного ПО или техники атаки, включая контекст и связанные детали. (__Reports__)
 - **Субъект угроз**: физические лица, группы или организации, которые, как считается, действуют со злым умыслом. (__Threat Actor__)
 - **Инструментарий**: характеризует свойства используемых программных инструментов и может использоваться в качестве основы для утверждения о том, как субъект угрозы использует их во время атаки. (__Tool__)
 - **Уязвимость**: ссылки на описания известных уязвимостей или описания уязвимостей нулевого дня, для которых еще нет внешнего определения. (__Vulnerability__)
 
### Stix Cyber-observable Objects:
 - **Артефакт**: позволяет хранить массив байтов в виде строки в кодировке base64 или связываться с полезной нагрузкой в ​​виде файла. (__Artifact__)
 - **Автономная система**: объект, описывающий автономную систему BGP. (__Autonomous System__)
 - **Директория**: объект представляет свойства, общие для каталога файловой системы (__Directory__)
 - **Доменное имя**: (__Domain Name__)
 - **Адрес электронной почты**: (__Email Address__)
 - **Электронное письмо**: соответствует формату электронного письма, описанного в стандарте RFC5322 и связанных RFC. (__Email Message__)
    - **MIME тип сообщения**: задает один компонент тела письма, состоящего из нескольких частей (__Email MIME Component Type__)
 - **Файл**: (**File**)
    - **Архив**: (__Archive File Extension__)
    - **NTFS объект**: (__NTFS File Extension__)
        - **Альтернативные потоки данных**: (__Alternate Data Stream Type__)
    - **PDF файл**: (__PDF File Extension__)
    - **Растровое изображение**: (__Raster Image File Extension__)
    - **Исполняемый файл Windows**: (__Windows PE Binary File Extension__)
        - **Заголовок исполняемого файла**: (__Windows PE Optional Header Type__)
        - **Секции исполняемого файла**: (__Windows PE Section Type__)
 - **Адрес IPv4**: (__IPv4 Address__)
 - **Адрес IPv6**: (__IPv6 Address__)
 - **MAC-адрес**: (__MAC Address__)
 - **Мьютекс**: (__Mutex__)
 - **Сетевой трафик**: (__Network Traffic__)
    - **Трафик HTTP запросов**: (__HTTP Request Extension__)
    - **Трафик ICMP**: (__ICMP Extension__)
    - **Трафик сетевых сокетов**: (__Network Socket Extension__)
    - **Трафик TCP**
 - **Процесс**: (__Process__)
    - **Процесс Windows**: (__Windows Process Extension__)
    - **Служба Windows**: (__Windows Service Extension__)
 - **ПО**: (__Software__)
 - **URL**: (__URL__)
 - **Пользовательские аккаунты**: представляет собой экземпляр любого типа учетной записи пользователя, включая, помимо прочего, операционную систему, устройство, службу обмена сообщениями и учетные записи платформы социальных сетей. (__User Account__)
    - **Пользовательские аккаунты UNIX**: UNIX Account Extension
 - **Ключ реестра Windows**: (__Windows Registry Key__)
    - **Значение ключа реестра Windows**: (__Windows Registry Value Type__)
 - **Сертификат X.509**: (__X.509 Certificate__)
    - **Сертификат Х.509 v.3**: (__X.509 v3 Extensions Type__)
