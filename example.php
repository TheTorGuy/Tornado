<?php

/*
* Tornado PHP Class Example
*
* Copyright (C) 2022 The Tor Guy <tordevstuff@protonmail.com>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// Plain text header for test output
header("Content-Type: text/plain");

// Require tornado class
require_once('inc/tornado.class.php');

// Configs: see class for public settings
// Save generated files to onions directory and chmod all to 0777
$configs = array('onionSaveDir' => 'onions', 'overridePermissions' => true);

// Initiate tornado class with configs
$tornado = new Tornado($configs);

// Generate 5 onion addresses
print "Generate 5 onion addresses:\n\n";
print_r($tornado->generateAddress(5));

// Generate 5 onion addresses, each with 3 authenticated clients
print "\nGenerate 5 onion addresses, each with 3 authenticated clients:\n\n";
print_r($tornado->generateAddress(5, 3));

// Generate 5 onion addresses, each with 3 authenticated named clients
print "\nGenerate 5 onion addresses, each with 3 authenticated named clients:\n\n";
$clients = array('Alice', 'Bob', 'Eve');
print_r($tornado->generateAddress(5, $clients));

// Generate 3 authenticated clients for existing onion address
print "\nGenerate 3 authenticated clients for existing onion address:\n\n";
print_r($tornado->generateAuthorization('2d7n3lfrcvxy3453jcrngiu3cov3cu6vxjrttes5pgvzjjeelwlt25ad.onion', 3));

// Generate 5 authenticated named clients for existing onion address
print "\nGenerate 5 authenticated named clients for existing onion address:\n\n";
$clients = array('Alice', 'Bob', 'Eve', 'John', 'Mallory');
print_r($tornado->generateAuthorization('lgxsp4kuccd4nhwganvtnyhqveojchn7ipnbelusurmqwzwndhblg3id.onion', $clients));


// Extras

// Validate onion address
#$tornado->validateAddress('cklhlxo7nblfdviy6pqpw64qlj6yu4rjl47ejsah6i7vfjxegnvlylid.onion'); // Returns true or false

// Verify hs_ed25519_public_key file
#$tornado->verifyPublicKeyFile('hs_ed25519_public_key'); // Returns true or false

// Verify hs_ed25519_secret_key file
#$tornado->verifySecretKeyFile('hs_ed25519_secret_key'); // Returns true or false

// Get onion address from hs_ed25519_public_key
#$tornado->getAddressFromPublicKeyFile('hs_ed25519_public_key'); // Returns string or false

// Get public key from onion address
#$tornado->getPublicKeyFromAddress('wcrwac2rggamyaekzbwno6dloxugktuw4ml4gx72ioa7th3j5guiksad.onion'); // Returns base64 string or false

// Get public key from onion address and save public key file
#$tornado->getPublicKeyFromAddress('wcrwac2rggamyaekzbwno6dloxugktuw4ml4gx72ioa7th3j5guiksad.onion', 'hs_ed25519_public_key');

// Get api string from hs_ed25519_secret_key file for use with ADD_ONION on the tor control port
#$tornado->getAPIStringFromSecretKeyFile('hs_ed25519_secret_key'); // Returns string or false


// Vanity - you're much better off using mkp224o for generating vanity addresses

// Generate 1 onion address starting with abc
#print "\nGenerate 1 onion address starting with abc:\n\n";
#print_r($tornado->generateAddress(1, '/^abc/i'));

// Generate 1 onion address starting with abc, with 3 authenticated clients
#print "\nGenerate 1 onion addresses starting with abc, with 3 authenticated clients:\n\n";
#print_r($tornado->generateAddress(1, 3, '/^abc/i'));

// Generate 1 onion address, containing abc, with 3 authenticated named clients
#print "\nGenerate 1 onion address, containing abc, with 3 authenticated named clients:\n\n";
#$clients = array('Alice', 'Bob', 'Eve');
#print_r($tornado->generateAddress(1, $clients, '/Abc/i'));
