package kerberosSim.client;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Client-Klasse
 */

import java.util.*;

import kerberosSim.dataStructure.Auth;
import kerberosSim.dataStructure.Ticket;
import kerberosSim.dataStructure.TicketResponse;
import kerberosSim.kdc.KDC;
import kerberosSim.server.Server;

public class Client extends Object {

	private KDC myKDC; // Konstruktor-Parameter

	private String currentUser; // Speicherung bei Login nï¿½tig
	private Ticket tgsTicket = null; // Speicherung bei Login nï¿½tig
	private long tgsSessionKey; // K(C,TGS) // Speicherung bei Login nï¿½tig

	private static final String TGS_SERVERNAME = "myTGS";
	private static final String COMMAND_SHOWFILE = "showFile";

	// Konstruktor
	public Client(KDC kdc) {
		myKDC = kdc;
	}

	/**
	 * Diese Mehtode holt TGSâ€�Ticket fÃ¼r den Ã¼bergebenen Benutzer vom KDC
	 * (AS) (TGSâ€�Servername: myTGS) und speichert diese zusammen mit dem
	 * TGSâ€�Sessionkey und dem UserNamen ab.
	 * 
	 * @param userName
	 *            Ã¼bergebenen Benutzer
	 * @param password
	 *            Ã¼bergebenes Passwort
	 * @return Status (Login ok / fehlgeschlagen)
	 */
	public boolean login(String userName, char[] password) {
		System.out.println("user login");

		/*
		 * Teil 1. Abholen des TGS-Ticket vom KDC fÃ¼r den Ã¼bergebenen Benutzer
		 * und dem TGS-Servername. Ebenfalls wird eine nonce (einmal Zahl)
		 * Ã¼bermittelt.
		 */
		long nonce = this.generateNonce();

		/*
		 * 1. Auf los schicken
		 */
		TicketResponse KDC_AS_ticketResponse = this.myKDC.requestTGSTicket(userName, TGS_SERVERNAME, nonce);

		/*
		 * 2. Erhalten und prüfen
		 */
		if (KDC_AS_ticketResponse != null) {
			/*
			 * Falls ein TicketRespone erhalten wird, mÃ¼ssen wir folgende
			 * Eigenschaften Ã¼berprÃ¼fen.
			 */

			/*
			 * PrÃ¼fen oder das TicketRespone bereits entschlÃ¼sselt ist oder ob
			 * der Key falsch ist und entschlüsselung des TicketRespone mit dem
			 * Key: Client
			 */

			if (!KDC_AS_ticketResponse.decrypt(this.generateSimpleKeyFromPassword(password))) {
				KDC_AS_ticketResponse.printError("error - dcrypting: password is incorrect");
				return false;

				/*
				 * PrÃ¼fen ob die Ã¼bermittelte nonce mit der erhaltenen nonce
				 * des TicketRespone Ã¼bereinstimmt. (replay attack)
				 */
			} else if (nonce != KDC_AS_ticketResponse.getNonce()) {
				KDC_AS_ticketResponse.printError("error - nonce: is incorrect");
				return false;

			} else {

				/*
				 * Teil 2. Wenn das TicketRespone valid ist, wird das Ticket,
				 * der SessionKey und der Username abgespeichert.
				 */

				/*
				 * 1. Setzen des Benutzernamen
				 */
				this.currentUser = userName;

				/*
				 * 2. Setzen des erhaltenen Ticket
				 */
				this.tgsTicket = KDC_AS_ticketResponse.getResponseTicket();

				/*
				 * Setzen des erhaltenen SessionsKey
				 */
				this.tgsSessionKey = KDC_AS_ticketResponse.getSessionKey();

				/*
				 * Ausgabe des ticketRespone
				 */
				KDC_AS_ticketResponse.print();

				return true;
			}

		} else {
			/*
			 * Wenn der TicketRespone als null zurÃ¼ckkommt, ist entweder der
			 * Benutzername oder der Servername falsch.
			 */
			System.out.println("error - login: username or tgsServer incorrect");
			return false;
		}

	}

	/**
	 * Diese Methode holt ein Serverticket vom KDC (TGS) und fordert den
	 * â€žshowFileâ€œâ€�Service beim Ã¼bergebenen Fileserver an.
	 * 
	 * 1. Authentifikation beim angegebenen Server.
	 * 
	 * 2. AusfÃ¼hrung der showFile des Servers.
	 * 
	 * @param fileServer
	 *            Ã¼bergebenen Fileserver
	 * @param filePath
	 *            filepath auf dem Ã¼bergebenen Server
	 * @return Status (BefehlsausfÃ¼hrung ok / fehlgeschlagen)
	 */
	public boolean showFile(Server fileServer, String filePath) {
		System.out.println("show file from client");

		/*
		 * Teil 1. beim KDC authentifizieren und Serverticket anfordern
		 */

		/*
		 * Authentifikation fÃ¼r den Benutzernamen erstellen.
		 */
		Auth authFor_KDC_TGS = new Auth(this.currentUser, System.currentTimeMillis());

		/*
		 * Authenfikation mit dem SessionKey(Client, TGS-Server) verschlÃ¼sseln.
		 */
		authFor_KDC_TGS.encrypt(tgsSessionKey);

		authFor_KDC_TGS.print();

		long nonce2 = this.generateNonce();

		/*
		 * Wir schicken Nachricht 3. los
		 */
		TicketResponse KDC_TGS_ticketResponse = this.myKDC.requestServerTicket(tgsTicket, authFor_KDC_TGS,
				fileServer.getName(), nonce2);
		/*
		 * und erhalten Nachricht 4.
		 */

		if (KDC_TGS_ticketResponse != null) {
			System.out.println("KDC_TGS_ticketResponse nicht null");
			/*
			 * Falls ein TicketRespone erhalten wird, mÃ¼ssen wir folgende
			 * Eigenschaften Ã¼berprÃ¼fen.
			 */

			/*
			 * PrÃ¼fen ob das TicketRespone bereits entschlÃ¼sselt ist oder ob
			 * der Key falsch ist. (Wie bei decrypt) ServerTicket entschlüsseln
			 * mit SessionKey(Client,TGS-Server)
			 */
			if (!KDC_TGS_ticketResponse.decrypt(this.tgsSessionKey)) {
				KDC_TGS_ticketResponse.printError("error - dcrypting: password is incorrect");
				return false;

				/*
				 * PrÃ¼fen ob die Ã¼bermittelte nonce mit der erhaltenen nonce
				 * des TicketRespone Ã¼bereinstimmt. (replay attack)
				 */
			} else if (nonce2 != KDC_TGS_ticketResponse.getNonce()) {
				KDC_TGS_ticketResponse.printError("error - nonce: is incorrect");
				return false;
			}
			/*
			 * 4. KDC_TGS_TicketRespone erfolgreich erhalten Ausgabe des
			 * ticketRespone
			 */
			KDC_TGS_ticketResponse.print();

			/*
			 * Teil 2. showFile ausfÃ¼hren Zusammenbau von 5.
			 */

			Auth authForServer = new Auth(this.currentUser, System.currentTimeMillis());

			/*
			 * Verschlüssen mit SessionKey(Client, Server)
			 */
			authForServer.encrypt(KDC_TGS_ticketResponse.getSessionKey());

			authForServer.print();

			/*
			 * Übermitteln von 5. an den Server S
			 */
			return fileServer.requestService(KDC_TGS_ticketResponse.getResponseTicket(), authForServer,
					COMMAND_SHOWFILE, filePath);

		} else {
			/*
			 * Wenn der TicketRespone als null zurÃ¼ckkommt, ist entweder der
			 * Benutzername oder der Servername falsch.
			 */
			System.out.println("error - login: username or fileServer incorrect");
			return false;
		}

	}

	/* *********** Hilfsmethoden **************************** */

	private long generateSimpleKeyFromPassword(char[] passwd) {
		// Liefert einen eindeutig aus dem Passwort abgeleiteten Schlï¿½ssel
		// zurï¿½ck, hier simuliert als long-Wert
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
