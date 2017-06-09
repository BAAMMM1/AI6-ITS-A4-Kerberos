package kerberos;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

public class Client extends Object {

	private KDC myKDC; // Konstruktor-Parameter

	private String currentUser; // Speicherung bei Login n�tig
	private Ticket tgsTicket = null; // Speicherung bei Login n�tig
	private long tgsSessionKey; // K(C,TGS) // Speicherung bei Login n�tig

	private static final String TGS_SERVERNAME = "myTGS";

	// Konstruktor
	public Client(KDC kdc) {
		myKDC = kdc;
	}

	/**
	 * Diese Mehtode holt TGS‐Ticket für den übergebenen Benutzer vom KDC (AS)
	 * (TGS‐Servername: myTGS) und speichert diese zusammen mit dem
	 * TGS‐Sessionkey und dem UserNamen ab.
	 * 
	 * @param userName
	 *            übergebenen Benutzer
	 * @param password
	 *            übergebenes Passwort
	 * @return Status (Login ok / fehlgeschlagen)
	 */
	public boolean login(String userName, char[] password) {

		/*
		 * 1. Nonce erstellen
		 */
		long nonce = this.generateNonce();

		/*
		 * 2. Abholen des TGS-Ticket vom KDC für den übergebenen Benutzer und
		 * dem TGS-Servername. Ebenfalls wird eine nonce (einmal Zahl)
		 * übermittelt.
		 */
		TicketResponse ticketResponse = this.myKDC.requestTGSTicket(userName, TGS_SERVERNAME, nonce);

		if (ticketResponse != null) {
			/*
			 * Falls ein TicketRespone erhalten wird, müssen wir folgende
			 * Eigenschaften überprüfen.
			 */

			/*
			 * Prüfen oder das TicketRespone bereits entschlüsselt ist oder ob
			 * der Key falsch ist. (Wie bei decrypt)
			 */
			if (!ticketResponse.isEncrypted()) {
				ticketResponse.printError("error - encrpyt: ticketRespone is not encrypted");
				return false;
			}

			/*
			 * Prüfen ob der Key falsch ist
			 */
			if (!ticketResponse.decrypt(this.generateSimpleKeyFromPassword(password))) {
				ticketResponse.printError("error - dcrypting: password is incorrect");
				return false;
			}

			/*
			 * Prüfen ob die übermittelte nonce mit der erhaltenen nonce des
			 * TicketRespone übereinstimmt. (replay attack)
			 */
			if (nonce != ticketResponse.getNonce()) {
				ticketResponse.printError("error - nonce: is incorrect");
				return false;
			}

			/*
			 * Wenn das TicketRespone valid ist, wird das Ticket, der SessionKey
			 * und der Username abgespeichert.
			 */

			/*
			 * 1. Setzen des Benutzernamen
			 */
			this.currentUser = userName;

			/*
			 * 2. Setzen des erhaltenen Ticket
			 */
			this.tgsTicket = ticketResponse.getResponseTicket();

			/*
			 * Setzen des erhaltenen SessionsKey
			 */
			this.tgsSessionKey = ticketResponse.getSessionKey();

			/*
			 * Ausgabe des ticketRespone
			 */
			ticketResponse.print();

			return true;

		} else {
			/*
			 * Wenn der TicketRespone als null zurückkommt, ist entweder der
			 * Benutzername oder der Servername falsch.
			 */
			System.out.println("error - login: username or tgsServer incorrect");
			return false;
		}

	}

	/**
	 * Diese Methode holt Serverticket vom KDC (TGS) und fordert den
	 * „showFile“‐Service beim übergebenen Fileserver an.
	 * 
	 * 1. Authentifikation beim angegebenen Server.
	 * 
	 * 2. Ausführung der showFile des Servers.
	 * 
	 * @param fileServer
	 *            übergebenen Fileserver
	 * @param filePath
	 *            filepath auf dem übergebenen Server
	 * @return Status (Befehlsausführung ok / fehlgeschlagen)
	 */
	public boolean showFile(Server fileServer, String filePath) {
		/* ToDo */
	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyFromPassword(char[] passwd) {
		// Liefert einen eindeutig aus dem Passwort abgeleiteten Schl�ssel
		// zur�ck, hier simuliert als long-Wert
		long pwKey = 0;
		if (passwd != null) {
			for (int i = 0; i < passwd.length; i++) {
				pwKey = pwKey + passwd[i];
			}
		}
		return pwKey;
	}

	private long generateNonce() {
		// Liefert einen neuen Zufallswert
		long rand = (long) (100000000 * Math.random());
		return rand;
	}
}
