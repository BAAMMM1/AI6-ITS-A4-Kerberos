package kerberosSim.kdc;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* KDC-Klasse
 */

import java.util.*;

import kerberosSim.dataStructure.Auth;
import kerberosSim.dataStructure.Ticket;
import kerberosSim.dataStructure.TicketResponse;

public class KDC extends Object {

	private final long tenHoursInMillis = 36000000; // 10 Stunden in
	// Millisekunden

	private final long fiveMinutesInMillis = 300000; // 5 Minuten in
	// Millisekunden

	/* *********** Datenbank-Simulation **************************** */

	private String tgsName; // TGS

	private long tgsKey; // K(TGS)

	private String user; // C

	private long userPasswordKey; // K(C)

	private String serverName; // S

	private long serverKey; // K(S)

	// Konstruktor
	public KDC(String name) {
		tgsName = name;
		// Eigenen Key fï¿½r TGS erzeugen (streng geheim!!!)
		tgsKey = generateSimpleKey();
	}

	public String getName() {
		return tgsName;
	}

	/* *********** Initialisierungs-Methoden **************************** */

	/*
	 * Diese Methode legt einen Server-Account in der Datenbank des KDC an und
	 * gibt einen geheimen SchlÃ¼ssel fÃ¼r den Server zurÃ¼ck.
	 */
	public long serverRegistration(String sName) {
		/*
		 * Server in der Datenbank registrieren. Rï¿½ckgabe: ein neuer geheimer
		 * Schlï¿½ssel fï¿½r den Server
		 */
		serverName = sName;
		// Eigenen Key fï¿½r Server erzeugen (streng geheim!!!)
		serverKey = generateSimpleKey();
		return serverKey;
	}

	/*
	 * TrÃ¤gt einen User in den Benutzerdatenbank ein und erstellt ein Key fÃ¼r
	 * das UserPassword.
	 */
	public void userRegistration(String userName, char[] password) {
		/*
		 * User registrieren --> Eintrag des Usernamens in die Benutzerdatenbank
		 */
		user = userName;
		userPasswordKey = generateSimpleKeyForPassword(password);

		System.out.println("Principal: " + user);
		System.out.println("Password-Key: " + userPasswordKey);
	}

	/* *********** AS-Modul: TGS - Ticketanfrage **************************** */

	public TicketResponse requestTGSTicket(String userName, String tgsServerName, long nonce) {
		/*
		 * Hier sind wir im KDC AS Schick 2. zurück
		 */

		/*
		 * Anforderung eines TGS-Tickets bearbeiten. Rï¿½ckgabe: TicketResponse
		 * fï¿½r die Anfrage
		 */
		long tgsSessionKey; // K(C,TGS)

		TicketResponse tgsTicketResp = null;
		Ticket tgsTicket = null;
		long currentTime = 0;

		// TGS-Antwort zusammenbauen
		if (userName.equals(user) && // Usernamen und Userpasswort in der
		// Datenbank suchen!
				tgsServerName.equals(tgsName)) {
			// OK, neuen Session Key fï¿½r Client und TGS generieren
			tgsSessionKey = generateSimpleKey();
			currentTime = (new Date()).getTime(); // Anzahl mSek. seit
			// 1.1.1970

			// Zuerst TGS-Ticket basteln ...
			tgsTicket = new Ticket(user, tgsName, currentTime, currentTime + tenHoursInMillis, tgsSessionKey);

			// ... dann verschlï¿½sseln ...
			tgsTicket.encrypt(tgsKey);

			// ... dann Antwort erzeugen
			tgsTicketResp = new TicketResponse(tgsSessionKey, nonce, tgsTicket);

			// ... und verschlï¿½sseln
			tgsTicketResp.encrypt(userPasswordKey);
		}
		return tgsTicketResp;
	}

	/*
	 * *********** TGS-Modul: Server - Ticketanfrage
	 * ****************************
	 */

	/**
	 * Diese Mehtode bearbeitet die Anfragen eines Server-Tickets. GehÃ¶rt zur
	 * TGS-FunktionalitÃ¤t.
	 * 
	 * @param tgsTicket
	 * @param tgsAuth
	 * @param serverName
	 * @param nonce
	 * @return TicketRespone fÃ¼r die Anfrage
	 */
	public TicketResponse requestServerTicket(Ticket tgsTicket, Auth tgsAuth, String serverName, long nonce) {
		System.out.println("KDC: requestServerTicket -------------------->");
		/*
		 * Hier sind wir im KDC TGS-Server 3. Erhalten und prüfen
		 */

		/*
		 * Entschlüsseln des TGS-Ticket mit dem Key des TGS-Server
		 */
		if (!tgsTicket.decrypt(this.tgsKey)) {
			tgsTicket.printError("error - tgsKey: key is invalid");
			return null;

			/*
			 * Entschlüsseln der Authentifikation des Client mit dem
			 * TGS-Sessionkey
			 */
		} else if (!tgsAuth.decrypt(tgsTicket.getSessionKey())) {
			tgsAuth.printError("error - tgsSessionKey: key is invalid");
			return null;

			/*
			 * Authentification überprüfen: Übereinstimmt der TGS-Ticket User
			 * mit dem Authentifikation User
			 */
		} else if (!tgsAuth.getClientName().equals(tgsTicket.getClientName())) {
			tgsAuth.printError("error - authentification: authentification client is invalid");
			return null;

			/*
			 * Ist der TGS-Ticket User in der Datenbank des KDC vorhanden?
			 */
		} else if (!user.equals(tgsTicket.getClientName())) {
			System.err.println("tgsTicket Client is not in the database");
			return null;

			/*
			 * Ist der Server vom Client angefordert in der Datenbank bekannt?
			 */
		} else if (!this.serverName.equals(serverName)) {
			System.err.println("servername is not in the database");
			return null;

			/*
			 * Ist die Zeit abgelaufen?
			 */
		} else if (!this.timeFresh(tgsAuth.getCurrentTime())) {
			tgsAuth.printError("error - authentification - time expirated");
			return null;

		} else if (!this.timeValid(tgsTicket.getStartTime(), tgsTicket.getEndTime())) {
			tgsTicket.printError("error - tgsTicket - time expirated");
			return null;

		} else {

			/*
			 * Alles ist gut 4. Zusammenbauen und los schicken
			 */

			/*
			 * Erstellung des Sessionkey(Client, TGS-Server)
			 */
			long sessionKeyClientServer = this.generateSimpleKey();

			/*
			 * Erstellung des ServerTicket
			 */
			Ticket serverTicket = new Ticket(tgsTicket.getClientName(), serverName, System.currentTimeMillis(),
					System.currentTimeMillis() + this.tenHoursInMillis, sessionKeyClientServer);

			/*
			 * Verschlüsseln des ServerTicket mit dem Key: Server
			 */
			serverTicket.encrypt(this.getServerKey(serverName));

			/*
			 * TicketRespone
			 */
			TicketResponse ticketResponse = new TicketResponse(sessionKeyClientServer, nonce, serverTicket);

			/*
			 * TicketRespone verschlüsseln mit dem SessionKey(Client, TGS-Server)
			 */
			ticketResponse.encrypt(tgsTicket.getSessionKey());

			return ticketResponse;
		}

	}

	/* *********** Hilfsmethoden **************************** */

	private long getServerKey(String sName) {
		// Liefert den zugehï¿½rigen Serverkey fï¿½r den Servernamen zurï¿½ck
		// Wenn der Servername nicht bekannt, wird -1 zurï¿½ckgegeben
		if (sName.equalsIgnoreCase(serverName)) {
			System.out.println("Serverkey ok");
			return serverKey;
		} else {
			System.out.println("Serverkey unbekannt!!!!");
			return -1;
		}
	}

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schlï¿½ssel fï¿½r ein Passwort zurï¿½ck, hier simuliert
		// als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateSimpleKey() {
		// Liefert einen neuen geheimen Schlï¿½ssel, hier nur simuliert als
		// long-Wert
		long sKey = (long) (100000000 * Math.random());
		return sKey;
	}

	private boolean timeValid(long lowerBound, long upperBound) {
		long currentTime = (new Date()).getTime(); // Anzahl mSek. seit
		// 1.1.1970
		if (currentTime >= lowerBound && currentTime <= upperBound) {
			return true;
		} else {
			System.out.println(
					"-------- Time not valid: " + currentTime + " not in (" + lowerBound + "," + upperBound + ")!");
			return false;
		}
	}

	private boolean timeFresh(long testTime) {
		// Wenn die ï¿½bergebene Zeit nicht mehr als 5 Minuten von der aktuellen
		// Zeit abweicht,
		// wird true zurï¿½ckgegeben
		long currentTime = (new Date()).getTime(); // Anzahl mSek. seit
		// 1.1.1970
		if (Math.abs(currentTime - testTime) < fiveMinutesInMillis) {
			return true;
		} else {
			System.out.println("-------- Time not fresh: " + currentTime + " is current, " + testTime + " is old!");
			return false;
		}
	}
}
