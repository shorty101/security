/******************************************************************************
 * ELEC5616/NETS3016
 * Computer and Network Security, The University of Sydney
 * Copyright (C) 2002-2004, Matt Barrie and Stephen Gould
 *
 * PROJECT:         StealthNet
 * FILENAME:        StealthNetServer.java
 * AUTHORS:         Matt Barrie and Stephen Gould
 * DESCRIPTION:     Implementation of StealthNet Server for ELEC5616/NETS3016
 *                  programming assignment.
 *                  This code has been written for the purposes of teaching
 *                  cryptography and computer security. It is to be used as
 *                  a demonstration only. No attempt has been made to optimise
 *                  the source code.
 * VERSION:         1.0-ICE
 *
 * REVISION HISTORY:
 *
 *****************************************************************************/

/* Import Libraries **********************************************************/

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/* StealthNetServer Class Definition *****************************************/

public class StealthNetServer {
	
	private final static BigInteger serverMod =   new BigInteger("20782787173762731228221560793184277311486335214070337155854804478858101086247824390049197181832159245577555779219855414634439395203923316975994364623073145700461123018358626191655578586668249695034575025882676101246536078936666054741126946084921344253707101698268557906668309106160476993013855462935152075469833054780696688733684279064964562426690119194129898391464050906105704476272569904165115645435458277103290404587372738539505344917709222862084316529105712722832889675983001885971961443244328389605146211109626101338590602714488312291024345909859735609958444051810949492112745342087756126201535317937795787830493");
	private final static BigInteger serverPribi = new BigInteger("7190590035629795849671542655071997315073205227261621603201362460260729696670116392943917879946354134206190049801031806869950002078962436675933781189681913709171246234055294702165040274237492742037459583317663008617501649295648302352183552840007804460881769550150900262961440239592731065147766492547027988941695870675177892042848243854015376165044311882259644249768557926074679077460601481556940624862654297639235504310374001191423904622293413245438600813314181118893008772021808411373176966007884007225430582296599905972630828433149872056278856902868364301080701477997000299492616260530175919194797757207881154521973");
	private final static BigInteger serverPubbi = new BigInteger("65537");
	private final static RSAPublicKeySpec serverPub = new RSAPublicKeySpec(serverMod, serverPubbi);
	private final static RSAPrivateKeySpec serverPri = new RSAPrivateKeySpec(serverMod, serverPribi);

	
    public static void main(String[] args) throws IOException {
        ServerSocket svrSocket = null;
        try {
            svrSocket = new ServerSocket(StealthNetComms.SERVERPORT);
        } catch (IOException e) {
            System.err.println("Could not listen on port: " + StealthNetComms.SERVERPORT);
            System.exit(1);
        }

        System.out.println("Server online...");
        while (true) {
            new StealthNetServerThread(svrSocket.accept(), serverPub, serverPri).start();
            System.out.println("Server accepted connection...");
        }
    }
}

/******************************************************************************
 * END OF FILE:     StealthNetServer.java
 *****************************************************************************/
 
