package kerberosSim;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver */

import java.util.*;

import kerberosSim.client.Client;
import kerberosSim.gui.PasswordDialog;
import kerberosSim.kdc.KDC;
import kerberosSim.server.Server;

public class KerberosSim {

	private KDC myKDC;
	private Client myClient;
	private Server myFileserver;

	public void initKerberos(String userName, char[] password, String serverName, String tgsName) {
		/* KDC initialisieren */
		myKDC = new KDC(tgsName);

		// Server initialisieren
		myFileserver = new Server(serverName);
		myFileserver.setupService(myKDC); // Schl�sselerzeugung und -austausch

		// User-Account und Client erzeugen
		myKDC.userRegistration(userName, password);
		myClient = new Client(myKDC);
	}

	public char[] readPasswd(String userName) {
		/*
		 * Passworteingabe �ber modalen Dialog. Liefert ein Passwort oder null
		 * bei Abbruch durch den Benutzer
		 */
		char[] password = null;
		PasswordDialog pwDialog = new PasswordDialog(userName);
		if (pwDialog.statusOK()) {
			password = pwDialog.getPassword();
		}
		return password;
	}

	public static void main(String args[]) {

		/*
		 * Simulation einer Benutzer-Session: Anmeldung und Zugriff auf
		 * Fileserver
		 */

		// -------- Start Initialisierung des Systems ------------------
		String userName = "axz467";
		char[] password = { 'S', 'e', 'c', 'r', 'e', 't', '!' };
		String serverName = "myFileserver";
		String tgsName = "myTGS";
		String filePath = "C:/Temp/ITS.txt";

		KerberosSim thisSession = new KerberosSim();

		// KDC + alle Server + Client initialisieren
		thisSession.initKerberos(userName, password, serverName, tgsName);

		// -------- Ende Initialisierung des Systems ------------------

		/* -------- Benutzersession simulieren ------ */
		// Passwort vom Benutzer holen
		System.out.println("Starte Login-Session f�r Benutzer: " + userName);

		/*
		 * Öffnet das Passwortdialogfesnter um vom Benutzter das Passwort zu
		 * erfragen.
		 */
		password = thisSession.readPasswd(userName);

		/*
		 * Falls ein Passwort übergeben wurde. Melde den Benutzer beim KDC an
		 * und lösche das übergebene Passwort im Hauptspeicher.
		 * 
		 *  Wenn der login fehlgeschlagen ist -> Ausgabe auf der Console.
		 *  Falls der login erfolgreich war -> Zugriff auf den FileServer
		 *  
		 *  Falls Zugriff auf den Server fehlgeschlagen ist -> Ausgabe auf der Console
		 */
		if (password != null) {

			// Benutzeranmeldung beim KDC
			boolean loginOK = thisSession.myClient.login(userName, password);

			// Passwort im Hauptspeicher l�schen (�berschreiben)!!
			Arrays.fill(password, ' ');

			
			if (!loginOK) {
				System.out.println("Login fehlgeschlagen!");
			} else {
				System.out.println("Login erfolgreich!\n");

				// Zugriff auf Fileserver
				boolean serviceOK = thisSession.myClient.showFile(thisSession.myFileserver, filePath);
				if (!serviceOK) {
					System.out.println("Zugriff auf Server " + serverName + " ist fehlgeschlagen!");
				}
			}
		}
	}

}
