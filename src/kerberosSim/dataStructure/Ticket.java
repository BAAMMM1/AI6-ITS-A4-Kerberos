package kerberosSim.dataStructure;

/* Simulation einer Kerberos-Session mit Zugriff auf einen Fileserver
 /* Ticket-Klasse
 */
import java.util.*;

public class Ticket extends Object {

	private String myClientName; // Konstruktor-Parameter

	private String myServerName; // Konstruktor-Parameter

	private long myStartTime; // Konstruktor-Parameter

	private long myEndTime; // Konstruktor-Parameter

	private long mySessionKey; // Konstruktor-Parameter

	// Geheimer Schl�ssel, mit dem das Ticket (simuliert) verschl�sselt ist:
	private long myTicketKey;

	private boolean isEncryptedState; // Aktueller Zustand des Objekts

	// Kalenderobjekt zur Zeitumrechnung (f�r Testausgaben)
	private Calendar cal;

	// Konstruktor
	public Ticket(String clientName, String serverName, long startTime,
			long endTime, long sessionKey) {

		myClientName = clientName;
		myServerName = serverName;
		myStartTime = startTime;
		myEndTime = endTime;
		mySessionKey = sessionKey;

		myTicketKey = -1;
		isEncryptedState = false;
		cal = new GregorianCalendar(); // f�r Testausgaben
	}

	public String getClientName() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sseltes Ticket (getClientName)");
		}
		return myClientName;
	}

	public String getServerName() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sseltes Ticket (getServerName)");
		}
		return myServerName;
	}

	public long getStartTime() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sseltes Ticket (getStartTime)");
		}
		return myStartTime;
	}

	public long getEndTime() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sseltes Ticket (getEndTime)");
		}
		return myEndTime;
	}

	public long getSessionKey() {
		if (isEncryptedState) {
			printError("Zugriff auf verschl�sseltes Ticket (getSessionKey)");
		}
		return mySessionKey;
	}

	public boolean encrypt(long key) {
		// Ticket mit dem Key verschl�sseln.
		// Falls das Ticket bereits verschl�sselt ist, wird false zur�ckgegeben.
		boolean encOK = false;
		if (isEncryptedState) {
			printError("Ticket ist bereits verschl�sselt");
		} else {
			myTicketKey = key;
			isEncryptedState = true;
			encOK = true;
		}
		return encOK;
	}

	public boolean decrypt(long key) {
		// Ticket mit dem Key entschl�sseln.
		// Falls der Key falsch ist oder
		// falls das Ticket bereits entschl�sselt ist, wird false zur�ckgegeben.
		boolean decOK = false;
		if (!isEncryptedState) {
			printError("Ticket ist bereits entschl�sselt");
		}
		if (myTicketKey != key) {
			printError("Ticket-Entschl�sselung mit key " + key
					+ " ist fehlgeschlagen");
		} else {
			isEncryptedState = false;
			decOK = true;
		}
		return decOK;
	}

	public boolean isEncrypted() {
		// Aktuellen Zustand zur�ckgeben: verschl�sselt (true) / entschl�sselt
		// (false)
		return isEncryptedState;
	}

	public void print() {
		System.out.println("********* Ticket f�r " + myClientName + " / "
				+ myServerName + " *******");
		System.out.println("StartTime: " + getDateString(myStartTime)
				+ " - EndTime: " + getDateString(myEndTime));
		System.out.println("Session Key: " + mySessionKey);
		System.out.println("Ticket Key: " + myTicketKey);
		if (isEncryptedState) {
			System.out.println("Ticket-Zustand: verschl�sselt (encrypted)!");
		} else {
			System.out.println("Ticket-Zustand: entschl�sselt (decrypted)!");
		}
	}

	public void printError(String message) {
		System.out.println("+++++++++++++++++++");
		System.out.println("+++++++++++++++++++ Fehler +++++++++++++++++++ "
				+ message + "! Ticket-Key: " + myTicketKey);
		System.out.println("+++++++++++++++++++");
	}

	private String getDateString(long time) {
		// Umrechnung der Zeitangabe time (Millisek. seit 1.1.1970) in einen
		// Datumsstring
		String dateString;

		cal.setTimeInMillis(time);
		dateString = cal.get(Calendar.DAY_OF_MONTH) + "."
				+ (cal.get(Calendar.MONTH) + 1) + "." + cal.get(Calendar.YEAR)
				+ " " + cal.get(Calendar.HOUR_OF_DAY) + ":"
				+ cal.get(Calendar.MINUTE) + ":" + cal.get(Calendar.SECOND)
				+ ":" + cal.get(Calendar.MILLISECOND);
		return dateString;
	}
}
