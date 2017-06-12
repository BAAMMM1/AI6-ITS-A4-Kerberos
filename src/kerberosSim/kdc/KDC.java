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
		// Eigenen Key f�r TGS erzeugen (streng geheim!!!)
		tgsKey = generateSimpleKey();
	}

	public String getName() {
		return tgsName;
	}

	/* *********** Initialisierungs-Methoden **************************** */

	/*
	 * Diese Methode legt einen Server-Account in der Datenbank des KDC an und
	 * gibt einen geheimen Schlüssel für den Server zurück.
	 */
	public long serverRegistration(String sName) {
		/*
		 * Server in der Datenbank registrieren. R�ckgabe: ein neuer geheimer
		 * Schl�ssel f�r den Server
		 */
		serverName = sName;
		// Eigenen Key f�r Server erzeugen (streng geheim!!!)
		serverKey = generateSimpleKey();
		return serverKey;
	}

	/*
	 * Trägt einen User in den Benutzerdatenbank ein und erstellt ein Key für
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
		 * Anforderung eines TGS-Tickets bearbeiten. R�ckgabe: TicketResponse
		 * f�r die Anfrage
		 */
		long tgsSessionKey; // K(C,TGS)

		TicketResponse tgsTicketResp = null;
		Ticket tgsTicket = null;
		long currentTime = 0;

		// TGS-Antwort zusammenbauen
		if (userName.equals(user) && // Usernamen und Userpasswort in der
		// Datenbank suchen!
				tgsServerName.equals(tgsName)) {
			// OK, neuen Session Key f�r Client und TGS generieren
			tgsSessionKey = generateSimpleKey();
			currentTime = (new Date()).getTime(); // Anzahl mSek. seit
			// 1.1.1970

			// Zuerst TGS-Ticket basteln ...
			tgsTicket = new Ticket(user, tgsName, currentTime, currentTime + tenHoursInMillis, tgsSessionKey);

			// ... dann verschl�sseln ...
			tgsTicket.encrypt(tgsKey);

			// ... dann Antwort erzeugen
			tgsTicketResp = new TicketResponse(tgsSessionKey, nonce, tgsTicket);

			// ... und verschl�sseln
			tgsTicketResp.encrypt(userPasswordKey);
		}
		return tgsTicketResp;
	}

	/*
	 * *********** TGS-Modul: Server - Ticketanfrage
	 * ****************************
	 */

	/**
	 * Diese Mehtode bearbeitet die Anfragen eines Server-Tickets. Gehört zur
	 * TGS-Funktionalität.
	 * 
	 * @param tgsTicket
	 * @param tgsAuth
	 * @param serverName
	 * @param nonce
	 * @return TicketRespone für die Anfrage
	 */
	public TicketResponse requestServerTicket(Ticket tgsTicket, Auth tgsAuth, String serverName, long nonce) {
		System.out.println("KDC: requestServerTicket -------------------->");
		/*
		 * Dycrypten
		 */
		if (!tgsTicket.decrypt(this.tgsKey)) {
			tgsTicket.printError("error - tgsKey: key is invalid");
			return null;

		} else if (!tgsAuth.decrypt(tgsTicket.getSessionKey())) {
			tgsAuth.printError("error - tgsSessionKey: key is invalid");
			return null;

			/*
			 * Authentification check
			 */
		} else if (!tgsAuth.getClientName().equals(tgsTicket.getClientName())) {
			tgsAuth.printError("error - authentification: authentification client is invalid");
			return null;

		} else if (!user.equals(tgsTicket.getClientName())) {
			System.out.println("tgsTicket Client is not in the database");
			return null;

		} else if (!serverName.equals(serverName)) {
			System.out.println("servername is not in the database");
			return null;

			/*
			 * Expiration check
			 */
		} else if (!this.timeFresh(tgsAuth.getCurrentTime())) {
			tgsAuth.printError("");
			return null;

		} else if (!this.timeValid(tgsTicket.getStartTime(), tgsTicket.getEndTime())) {
			tgsTicket.printError("");
			return null;

		} else {

			/*
			 * All is alright
			 * 
			 * ServerTicket
			 */
			long sessionKeyServer = this.generateSimpleKey();

			Ticket serverTicket = new Ticket(tgsTicket.getClientName(), serverName, System.currentTimeMillis(),
					System.currentTimeMillis() + this.fiveMinutesInMillis, sessionKeyServer);

			/*
			 * Encrypt with serverKey
			 */
			serverTicket.encrypt(this.getServerKey(serverName));

			/*
			 * TicketRespone
			 */
			TicketResponse ticketResponse = new TicketResponse(sessionKeyServer, nonce, serverTicket);

			ticketResponse.encrypt(tgsTicket.getSessionKey());

			return ticketResponse;
		}

	}

	/* *********** Hilfsmethoden **************************** */

	private long getServerKey(String sName) {
		// Liefert den zugeh�rigen Serverkey f�r den Servernamen zur�ck
		// Wenn der Servername nicht bekannt, wird -1 zur�ckgegeben
		if (sName.equalsIgnoreCase(serverName)) {
			System.out.println("Serverkey ok");
			return serverKey;
		} else {
			System.out.println("Serverkey unbekannt!!!!");
			return -1;
		}
	}

	private long generateSimpleKeyForPassword(char[] pw) {
		// Liefert einen Schl�ssel f�r ein Passwort zur�ck, hier simuliert als
		// long-Wert
		long pwKey = 0;
		for (int i = 0; i < pw.length; i++) {
			pwKey = pwKey + pw[i];
		}
		return pwKey;
	}

	private long generateSimpleKey() {
		// Liefert einen neuen geheimen Schl�ssel, hier nur simuliert als
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
		// Wenn die �bergebene Zeit nicht mehr als 5 Minuten von der aktuellen
		// Zeit abweicht,
		// wird true zur�ckgegeben
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
