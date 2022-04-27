<?php

/*
* Tornado PHP Class
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

class Tornado {

	public static $authorizedClientFilePrivateSuffix = '.auth_private';
	public static $clientsKeysCSV = 'client_keys.csv';
	public static $clientsKeysDir = 'client_keys';
	public static $defaultClientName = 'client';
	public static $disableSaveFiles = false;
	public static $disableCSVFile = false;
	public static $jsonResponse = false;
	public static $onionSaveDir = 'onions';
	public static $overridePermissions = false;

	protected static $addressDirChmod = 0700;
	protected static $authorizedClientDirChmod = 0700;
	protected static $authorizedClientFileSuffix = '.auth';
	protected static $authorizedClientsDir = 'authorized_clients';
	protected static $basePath = '';
	protected static $clientsKeysFilesAndDirChmod = 0755;
	protected static $descriptorDelimiter = ':';
	protected static $descriptorName = 'descriptor';
	protected static $descriptorType = 'x25519';
	protected static $expandSecretKeyHashAlgo = 'sha512';
	protected static $hostNameFile = 'hostname';
	protected static $onionChecksum = '.onion checksum';
	protected static $onionDomainLength= 56;
	protected static $onionFilesChmod = 0600;
	protected static $onionHashAlgo = 'sha3-256';
	protected static $onionSaveDirChmod = 0755;
	protected static $onionTLD = '.onion';
	protected static $onionVersion = "\x03";
	protected static $overrideChmod = 0777;
	protected static $publicKeyFileHeader = '== ed25519v1-public: type0 ==' . "\x00\x00\x00";
	protected static $publicKeyFileName = 'hs_ed25519_public_key';
	protected static $secretKeyFileHeader = '== ed25519v1-secret: type0 ==' . "\x00\x00\x00";
	protected static $secretKeyFileName = 'hs_ed25519_secret_key';
	
	public function __construct()
	{
		if (!function_exists('sodium_crypto_sign_keypair'))
			exit('Sodium required. The sodium extension is bundled with PHP since PHP 7.2.0. For older PHP versions, sodium is available via PECL.');
		if (!empty(func_get_args()))
		{
			$props = array();
			$reflect = new ReflectionObject($this);
			foreach($reflect->getProperties(ReflectionProperty::IS_PUBLIC) as $prop)
				array_push($props, $prop->name);
			foreach (func_get_args()[0] as $key => $val)
				if (isset(self::${$key}) && in_array($key, $props))
					self::${$key} = $val;
			if (self::$overridePermissions == true)
				foreach (array('addressDirChmod', 'authorizedClientDirChmod', 'clientsKeysFilesAndDirChmod', 'onionFilesChmod', 'onionSaveDirChmod') as $key)
					self::${$key} = self::$overrideChmod;
		}
		self::$basePath = rtrim(self::$onionSaveDir, '/\\');
	}

	public function generateAddress($limit=1, $clients=0)
	{
		$count = 1; $result = array();
		do
		{
			$newKeyPair = sodium_crypto_sign_keypair();
			$secretKey = sodium_crypto_sign_secretkey($newKeyPair);
			$publicKey = sodium_crypto_sign_publickey($newKeyPair);
			$onionAddress = self::encodePublicKey($publicKey);
			$result[$count-1]['address'] = $onionAddress;
			if ($clients > 0 || is_array($clients))
				$result[$count-1]['clients'] = array_values(self::generateAuthorization($onionAddress, $clients, false)['clients']);
			$result[$count-1][self::$publicKeyFileName . '_base64'] = base64_encode($publicKey);
			$result[$count-1][self::$secretKeyFileName . '_base64'] = base64_encode($secretKey);
			if (!self::$disableSaveFiles)
			{
				TornadoHelper::saveAddress($onionAddress, $publicKey, $secretKey);
				$saveFilePath = self::$basePath . '/' . $onionAddress;
				$result[$count-1][self::$publicKeyFileName . '_file'] = $saveFilePath . '/' . self::$publicKeyFileName;
				$result[$count-1][self::$secretKeyFileName . '_file'] = $saveFilePath . '/' . self::$secretKeyFileName;
				$result[$count-1][self::$hostNameFile . '_file'] = $saveFilePath . '/' . self::$hostNameFile;
			}
			ksort ($result[$count-1]);
			$count++;
		} while ($count <= $limit);
		return self::$jsonResponse ? json_encode($result) : $result;
	}

	public function generateAuthorization($onionAddress, $limit=1, $direct=true)
	{
		$clients = ''; $count = 1;  $list = ''; $result = array();
		if (!TornadoHelper::validateAddress($onionAddress))
			return false;
		if (is_array($limit))
		{
			$clients = $limit;
			$limit = count($limit);
		}
		if ($direct == true)
			$result['address'] = $onionAddress;
		$onionAddressNoTLD = str_ireplace(self::$onionTLD, '', trim(strtolower($onionAddress)));
		$keyPath = self::$basePath . '/' . $onionAddress . '/' . self::$clientsKeysDir;
		$clientPath = self::$basePath . '/' . $onionAddress . '/' . self::$authorizedClientsDir;
		TornadoHelper::createDirectory($keyPath, self::$clientsKeysFilesAndDirChmod, true);
		TornadoHelper::createDirectory($clientPath, self::$authorizedClientDirChmod, true);
		do
		{
			$client = is_array($clients) ? TornadoHelper::sanitizeClient($clients[$count-1]) : self::$defaultClientName . $count;
			$newKeyPair = sodium_crypto_sign_keypair();
			$secretKey = TornadoHelper::b32Tor(sodium_crypto_sign_ed25519_sk_to_curve25519(sodium_crypto_sign_secretkey($newKeyPair)));
			$publicKey = TornadoHelper::b32Tor(sodium_crypto_sign_ed25519_pk_to_curve25519(sodium_crypto_sign_publickey($newKeyPair)));
			$secretAuthLine = $onionAddressNoTLD . self::$descriptorDelimiter . self::$descriptorName . self::$descriptorDelimiter . self::$descriptorType . self::$descriptorDelimiter . $secretKey;
			$secretSavePath = $keyPath . '/' . $client . self::$authorizedClientFilePrivateSuffix;
			$publicAuthLine = self::$descriptorName . self::$descriptorDelimiter . self::$descriptorType . self::$descriptorDelimiter . $publicKey;
			$publicSavePath = $clientPath . '/' . $client . self::$authorizedClientFileSuffix;
			TornadoHelper::saveFile($secretSavePath, $secretAuthLine . "\n", self::$clientsKeysFilesAndDirChmod);
			TornadoHelper::saveFile($publicSavePath, $publicAuthLine . "\n", self::$onionFilesChmod);
			if (!self::$disableSaveFiles)
			{
				$list.= '"' . $client . '","' . $secretKey . '"' . "\n";
				$result['clients'][$count-1]['public_hs_server_file'] = $publicSavePath;
				$result['clients'][$count-1]['secret_tb_client_file'] = $secretSavePath;
			}
			$result['clients'][$count-1][self::$defaultClientName] = $client;
			$result['clients'][$count-1]['public_hs_server_key'] = $publicKey;
			$result['clients'][$count-1]['public_hs_server_str'] = $publicAuthLine;
			$result['clients'][$count-1]['secret_tb_client_key'] = $secretKey;
			$result['clients'][$count-1]['secret_tb_client_str'] = $secretAuthLine;
			ksort ($result['clients'][$count-1]);
			$count++;
		} while ($count <= $limit);
		if (!self::$disableCSVFile)
			TornadoHelper::saveFile(self::$basePath . '/' . $onionAddress . '/' . self::$clientsKeysCSV, $list . "\n", self::$clientsKeysFilesAndDirChmod);
		return self::$jsonResponse && $direct ? json_encode($result) : $result;
	}

	protected static function encodePublicKey($publicKey)
	{
		return TornadoHelper::b32Tor($publicKey . substr(hash(self::$onionHashAlgo, self::$onionChecksum . $publicKey . self::$onionVersion, true), 0, 2) . self::$onionVersion) . self::$onionTLD;
	}

	protected static function expandSecretKey($secretKey)
	{
		$hash = array_values(unpack('C*', hex2bin(hash(self::$expandSecretKeyHashAlgo, substr($secretKey, 0, SODIUM_CRYPTO_BOX_SECRETKEYBYTES)))));
		$hash[0] &= 248;
		$hash[31] &= 127;
		$hash[31] |= 64;
		return call_user_func_array('pack', array_merge(array('C*'), $hash));
	}
}

class TornadoHelper extends Tornado {

	protected static function b32Tor($enc)
	{
		$b32 =''; $bin ='';
		$enc = str_split($enc);
		$set = array_merge(range('a', 'z'), range(2, 7));
		for($i = 0; $i < count($enc); $i++)
			$bin.= str_pad(base_convert(ord($enc[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
		$bit = str_split($bin, 5);
		$len = count($bit);
		for ($i = 0; $i <= $len; $i++)
			if (isset($bit[$i]))
				$b32.= $set[base_convert(str_pad($bit[$i], 5, '0'), 2, 10)];
		return $len == parent::$onionDomainLength ? $b32 : strtoupper($b32);
	}

	protected static function createDirectory($path, $chmod, $recursive=false)
	{
		$path = rtrim($path, '/\\');
		if (!parent::$disableSaveFiles)
			if (!file_exists($path) || !is_dir($path))
				mkdir($path, $chmod, $recursive);
	}

	protected static function sanitizeClient($client)
	{
		return strtolower(preg_replace(array('[^\w.-]', '/\s+/'), array('', '_'), trim($client)));
	}

	protected static function saveAddress($onionAddress, $publicKey, $secretKey)
	{
		$savePath = parent::$basePath . '/' . $onionAddress;
		self::createDirectory(parent::$basePath, parent::$onionSaveDirChmod);
		self::createDirectory($savePath, parent::$addressDirChmod);
		self::createDirectory($savePath . '/' . parent::$authorizedClientsDir, parent::$authorizedClientDirChmod);
		self::saveFile($savePath . '/' . parent::$hostNameFile, $onionAddress."\n", parent::$onionFilesChmod);
		self::saveFile($savePath . '/' . parent::$publicKeyFileName, parent::$publicKeyFileHeader . $publicKey, parent::$onionFilesChmod);
		self::saveFile($savePath . '/' . parent::$secretKeyFileName, parent::$secretKeyFileHeader . parent::expandSecretKey($secretKey), parent::$onionFilesChmod);
	}

	protected static function saveFile($path, $data, $chmod=0755)
	{
		if (!parent::$disableSaveFiles)
		{
			file_put_contents($path, $data);
			chmod($path, $chmod);
		}
	}

	protected static function validateAddress($address)
	{
		$address = strtok(trim(strtolower($address)), '.');
		if (preg_match('/^[a-z2-7]+$/', $address) && substr($address, -1) == 'd' && strlen($address) == parent::$onionDomainLength)
			return true;
		return false;
	}
}
