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

	private String currentUser; // Speicherung bei Login n�tig
	private Ticket tgsTicket = null; // Speicherung bei Login n�tig
	private long tgsSessionKey; // K(C,TGS) // Speicherung bei Login n�tig

	private static final String TGS_SERVERNAME = "myTGS";
	private static final String COMMAND_SHOWFILE = "showFile";

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
		System.out.println("user login");

		/*
		 * Teil 1. Abholen des TGS-Ticket vom KDC für den übergebenen Benutzer
		 * und dem TGS-Servername. Ebenfalls wird eine nonce (einmal Zahl)
		 * übermittelt.
		 */
		long nonce = this.generateNonce();
		
		System.out.println("");
		
		TicketResponse myKDCTGSTicketResponse = this.myKDC.requestTGSTicket(userName, TGS_SERVERNAME, nonce);

		if (myKDCTGSTicketResponse != null) {
			System.out.println("1");
			/*
			 * Falls ein TicketRespone erhalten wird, müssen wir folgende
			 * Eigenschaften überprüfen.
			 */

			/*
			 * Prüfen oder das TicketRespone bereits entschlüsselt ist oder ob
			 * der Key falsch ist. (Wie bei decrypt)
			 */
			
			if (!myKDCTGSTicketResponse.decrypt(this.generateSimpleKeyFromPassword(password))) {
				System.out.println("2");
				myKDCTGSTicketResponse.printError("error - dcrypting: password is incorrect");
				return false;
				
				/*
				 * Prüfen ob die übermittelte nonce mit der erhaltenen nonce des
				 * TicketRespone übereinstimmt. (replay attack)
				 *  */
			} else if (nonce != myKDCTGSTicketResponse.getNonce()) {
				System.out.println("3");
				
				myKDCTGSTicketResponse.printError("error - nonce: is incorrect");
				return false;
			}

			System.out.println("4");
			/*
			 * Teil 2. Wenn das TicketRespone valid ist, wird das Ticket, der
			 * SessionKey und der Username abgespeichert.
			 */

			/*
			 * 1. Setzen des Benutzernamen
			 */
			this.currentUser = userName;

			/*
			 * 2. Setzen des erhaltenen Ticket
			 */
			this.tgsTicket = myKDCTGSTicketResponse.getResponseTicket();

			/*
			 * Setzen des erhaltenen SessionsKey
			 */
			this.tgsSessionKey = myKDCTGSTicketResponse.getSessionKey();

			/*
			 * Ausgabe des ticketRespone
			 */
			myKDCTGSTicketResponse.print();

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
	 * Diese Methode holt ein Serverticket vom KDC (TGS) und fordert den
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
		System.out.println("show file from client");

		/*
		 * Teil 1. beim KDC authentifizieren und Serverticket anfordern
		 */

		/*
		 * Authentifikation für den Benutzernamen erstellen.
		 */
		Auth authentifikation = new Auth(this.currentUser, System.currentTimeMillis());
		
		/*
		 * Authenfikation mit dem SessionKey verschlüsseln.
		 */
		authentifikation.encrypt(tgsSessionKey);
		
		authentifikation.print();
	

		long nonce = this.generateNonce();

		TicketResponse serverTicketTicketResponse = this.myKDC.requestServerTicket(tgsTicket, authentifikation,
				fileServer.getName(), nonce);
		
		if (serverTicketTicketResponse != null) {
			System.out.println("serverticket nicht null");
			/*
			 * Falls ein TicketRespone erhalten wird, müssen wir folgende
			 * Eigenschaften überprüfen.
			 */

			/*
			 * Prüfen oder das TicketRespone bereits entschlüsselt ist oder ob
			 * der Key falsch ist. (Wie bei decrypt)
			 * Achtung decrypt mit dem tgsSessionKey
			 */
			if (!serverTicketTicketResponse.decrypt(this.tgsSessionKey)) {
				System.out.println("1");
				serverTicketTicketResponse.printError("error - dcrypting: password is incorrect");
				return false;
				
				/*
				 * Prüfen ob die übermittelte nonce mit der erhaltenen nonce des
				 * TicketRespone übereinstimmt. (replay attack)
				 */
			} else if (nonce != serverTicketTicketResponse.getNonce()) {
				System.out.println("2");
				serverTicketTicketResponse.printError("error - nonce: is incorrect");
				return false;
			}
			System.out.println("4");
			/*
			 * Ausgabe des ticketRespone
			 */
			serverTicketTicketResponse.print();
			
			/*
			 * Teil 2. Beim Server atuhentifizieren und showFile ausführen
			 */

			Auth serverAuthentifikation = new Auth(this.currentUser, System.currentTimeMillis());

			serverAuthentifikation.encrypt(serverTicketTicketResponse.getSessionKey());
			
			serverAuthentifikation.print();						

			return fileServer.requestService(serverTicketTicketResponse.getResponseTicket(), serverAuthentifikation,
					COMMAND_SHOWFILE, filePath);

		} else {
			/*
			 * Wenn der TicketRespone als null zurückkommt, ist entweder der
			 * Benutzername oder der Servername falsch.
			 */
			System.out.println("error - login: username or fileServer incorrect");
			return false;
		}

		

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
