<?php

/*
    This file is part of Dash Ninja.
    https://github.com/elbereth/dashninja-be

    Dash Ninja is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Dash Ninja is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Dash Ninja.  If not, see <http://www.gnu.org/licenses/>.

 */

/*****************************************************************************
 * Dash Ninja Back-end Private REST API                                      *
 *---------------------------------------------------------------------------*
 * This script is the backend interface between hubs                         *
 * It is the foundation for all other scripts, it is private API and is not  *
 * meant to be public.                                                       *
 *                                                                           *
 * Identification of peers is done via SSL client certificates               *
 *                                                                           *
 * Required:                                                                 *
 * Phalcon PHP extension - http://phalconphp.com                             *
 *****************************************************************************/

require_once('libs/db.inc.php');

// =================================================
// Authenticate the remote peer (Before the Routing)
// =================================================
// Done via the EventManager and beforeHandleRoute event

// By default peer is not authenticated:
$authinfo = false;

// Create a events manager
$eventManager = new Phalcon\Events\Manager();

// Attach the anonymous function to handle the authentication of the peer
$eventManager->attach('micro', function($event, $app) use ($mysqli) {
  global $authinfo;

  if ($event->getType() == 'beforeHandleRoute') {

    // The server should have the TLS client certificate information and the remote peer address
    // If not, just fail early
    if (!array_key_exists("VERIFIED",$_SERVER) || ($_SERVER['VERIFIED'] != "SUCCESS")
     || !array_key_exists("DN",$_SERVER) || (strlen($_SERVER['DN'])==0)
     || !array_key_exists("REMOTE_ADDR",$_SERVER) || (strlen($_SERVER['REMOTE_ADDR'])==0)) {
      $response = new Phalcon\Http\Response();
      $response->setStatusCode(401, "Unauthorized");
      //Send errors to the client
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Missing/Wrong TLS client certificate')));
      $response->send();
      return false;
    }
    // The server could not connect to the MySQL database
    // Means we are out of business
    elseif ($mysqli->connect_errno != 0) {
      $response = new Phalcon\Http\Response();
      //Change the HTTP status
      $response->setStatusCode(503, "Service Unavailable");
      //Send errors to the client
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('No DB connection ('.$mysqli->connect_errno.': '.$mysqli->connect_error.')')));
      $response->send();
      return false;
    }
    // Now we need to check the peer is a known/allowed hub (via its client certificate and the remote address)
    $cacheserial = sha1($_SERVER['DN']);
    $cacheserial2 = sha1($_SERVER['REMOTE_ADDR']);
    $cachefnam = CACHEFOLDER.sprintf("dashninja_cmd_hubcheck_%s_%s",$cacheserial,$cacheserial2);
    $cachevalid = (is_readable($cachefnam) && ((filemtime($cachefnam)+7200)>=time()));
    if ($cachevalid) {
      $data = unserialize(file_get_contents($cachefnam));
      $result = $data["result"];
      $authinfo = $data["authinfo"];
    }
    else {
      $sql = "SELECT HubId, HubEnabled, HubDescription FROM cmd_hub WHERE HubCertificate = '%s' AND HubIPv6 = inet6_aton('%s')";
      $sqlx = sprintf($sql,$mysqli->real_escape_string($_SERVER['DN'])
                          ,$mysqli->real_escape_string($_SERVER['REMOTE_ADDR']));
      $result = $mysqli->query($sqlx);
      if ($result !== false) {
        // If the query is a success, we retrieve the first result (should be the only one)
        $authinfo = $result->fetch_assoc();
        $result->close();
      }
      $data = array("result" => $result, "authinfo" => $authinfo);
      file_put_contents($cachefnam,serialize($data),LOCK_EX);
    }
    // If the query failed, something is wrong with MySQL
    // Means we are out of business
    if ($result === false) {
      $response = new Phalcon\Http\Response();
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
      $response->send();
      $authinfo = false;
      return false;
    }
    else {
      // If the query result is null, then the remote peer is NOT authorized
      if (is_null($authinfo)) {
        $response = new Phalcon\Http\Response();
        $response->setStatusCode(401, "Unauthorized");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('TLS client certificate did not match a known hub',$_SERVER['DN'],$_SERVER['REMOTE_ADDR'],$sql,$sqlx)));
        $response->send();
        $authinfo = false;
        return false;
      }
      // The remote is known, but disabled, deny the access
      elseif ($authinfo['HubEnabled'] != '1') {
        $response = new Phalcon\Http\Response();
        $response->setStatusCode(401, "Unauthorized");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Hub is disabled (Access denied)')));
        $response->send();
        return false;
      }
      // We passed! Peer is authorized!
    }
  }

});

//Create and bind the DI to the application
$app = new \Phalcon\Mvc\Micro();
$app->setEventsManager($eventManager);

$router = $app->getRouter();
//$router->setUriSource(\Phalcon\Mvc\Router::URI_SOURCE_SERVER_REQUEST_URI);

// ============================================================================
// BALANCES (for dmnbalance)
// ----------------------------------------------------------------------------
// End-point to retrieve all pubkeys and last updates
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/balances', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    // Retrieve all known nodes for current hub
    $sql = "SELECT TestNet, PubKey, LastUpdate FROM cmd_info_masternode_balance";
    $mnpubkeys = array();
    $tnpubkeys = array();
    if ($result = $mysqli->query($sql)) {
      while($row = $result->fetch_assoc()){
        $date = new DateTime($row['LastUpdate']);
        $row['LastUpdate'] = $date->getTimestamp();
        if ($row['TestNet'] == 1) {
          $tnpubkeys[$row['PubKey']] = $row['LastUpdate'];
        }
        else {
          $mnpubkeys[$row['PubKey']] = $row['LastUpdate'];
       }
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('balances' => array('testnet' => $tnpubkeys,
                                                                                            'mainnet' => $mnpubkeys))));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// BALANCES (Reporting for dmnbalance)
// ----------------------------------------------------------------------------
// End-point for the balance report
// HTTP method:
//   POST
// Parameters (JSON body):
//   array of balance information (mandatory)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/balances', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !is_array($payload) || (count($payload) == 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {

    $sqlbal = array();
    foreach($payload as $node) {
      $sqlbal[] = sprintf("(%d,'%s',%.9f,'%s')",
                                  $node['TestNet'],
                                  $mysqli->real_escape_string($node['PubKey']),
                                  $node['Balance'],
                                  $mysqli->real_escape_string($node['LastUpdate'])
                                );
    }

    $sql = "INSERT INTO cmd_info_masternode_balance (TestNet, PubKey, Balance, LastUpdate)"
                           ." VALUES ".implode(',',$sqlbal)
            ." ON DUPLICATE KEY UPDATE Balance = VALUES(Balance), LastUpdate = VALUES(LastUpdate)";

    if ($result = $mysqli->query($sql)) {
      $info = $mysqli->info;
      if (is_null($info)) {
        $info = true;
      }

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('balances' => $info)));

    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// BLOCKSGAPS (data for dmnblockdegapper)
// ----------------------------------------------------------------------------
// End-point for the balance report
// HTTP method:
//   GET
// Parameters (JSON body):
//   testnet=0|1
//   interval=interval (optional, default is P1D for 1 day)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of blocks (only is status is OK)
// ============================================================================
$app->get('/blocksgaps', function() use ($app,&$mysqli) {

    //Create a response
    $response = new Phalcon\Http\Response();

    $request = $app->request;

    $errmsg = array();

    if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
        $errmsg[] = "No CONTENT expected";
    }

    // Retrieve the 'testnet' parameter
    if ($request->hasQuery('testnet')) {
        $testnet = intval($request->getQuery('testnet'));
        if (($testnet != 0) && ($testnet != 1)) {
            $testnet = 0;
        }
    }
    else {
        $testnet = 0;
    }

    // Retrieve the 'interval' parameter
    if ($request->hasQuery('interval')) {
        try {
            $interval = new DateInterval($request->getQuery('interval'));
        } catch (Exception $e) {
            $errmsg[] = 'Wrong interval parameter';
            $interval = new DateInterval('P1M');
        }
    }
    else {
        $interval = new DateInterval('P1M');
    }
    $interval->invert = 1;
    $datefrom = new DateTime();
    $datefrom->add( $interval );
    $datefrom = $datefrom->getTimestamp();

    if (count($errmsg) > 0) {
        //Change the HTTP status
        $response->setStatusCode(400, "Bad Request");

        //Send errors to the client
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => $errmsg));
    }
    else {
        $sql = sprintf("SELECT BlockId FROM cmd_info_blocks WHERE BlockTestNet = %d AND BlockTime >= %d ORDER BY BlockId DESC",$testnet,$datefrom);
        $blocks = array();
        if ($result = $mysqli->query($sql)) {
            while($row = $result->fetch_array(MYSQLI_NUM)){
                $blocks[intval($row[0])] = intval($row[0]);
            }

            //Change the HTTP status
            $response->setStatusCode(200, "OK");
            $response->setJsonContent(array('status' => 'OK', 'data' => $blocks));
        }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        }
    }
    return $response;

});

// ============================================================================
// BLOCKS (Reporting for dmnblockparser)
// ----------------------------------------------------------------------------
// End-point for the balance report
// HTTP method:
//   POST
// Parameters (JSON body):
//   array of:
//     blockshistory (mandatory, can be empty array)
//     blocksinfo (mandatory, can be empty array)
//   (Both cannot be empty)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/blocks', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !is_array($payload) || !array_key_exists('blockshistory',$payload) || !is_array($payload['blockshistory'])
   || !array_key_exists('blocksinfo',$payload) || !is_array($payload['blocksinfo'])
   || ((count($payload['blockshistory']) == 0) && (count($payload['blocksinfo']) == 0))) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing',"cbh=".count($payload['blockshistory'])." cbi=".count($payload['blocksinfo']),var_export($payload,true))));
  }
  else {
    // Retrieve all known nodes for current hub
    $result = dashninja_cmd_getnodes($mysqli,$authinfo['HubId'],0);
    $numnodes = 0;
    $nodes = array();
    if (count($result) > 0) {
      foreach($result as $nodename => $row){
        $numnodes++;
        $nodes[$nodename] = $row['NodeId'];
      }
    }
    $result = dashninja_cmd_getnodes($mysqli,$authinfo['HubId'],1);
    if (count($result) > 0) {
        foreach($result as $nodename => $row){
            $numnodes++;
            $nodes[$nodename] = $row['NodeId'];
        }
    }
    if ($numnodes == 0) {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('No nodes found')));
    }
    else {
      $stats = array();
      $bhsql = array();
      $curratio = array(-1,-1);
      foreach($payload['blockshistory'] as $bhentry) {
        if (!array_key_exists($bhentry['FromNodeUserName'],$nodes)) {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
          return $response;
        }
        $bhsql[] = sprintf("(%d,%d,%d,'%s','%s',%d,%.8f)",$bhentry['BlockHeight'],
                                                     $bhentry['BlockTestNet'],
                                                     $nodes[$bhentry['FromNodeUserName']],
                                                     $mysqli->real_escape_string($bhentry['BlockMNPayee']),
                                                     $mysqli->real_escape_string($bhentry['LastUpdate']),
                                                     $bhentry['Protocol'],
                                                     $bhentry['BlockMNRatio']);
        if ($bhentry['BlockMNRatio'] > $curratio[$bhentry['BlockTestNet']]) {
          $curratio[$bhentry['BlockTestNet']] = $bhentry['BlockMNRatio'];
        }
      }
      $bhinfo = false;
      if (count($bhsql) > 0) {
        $sql = "INSERT INTO cmd_info_blocks_history2 (BlockHeight, BlockTestNet, NodeID, BlockMNPayee, LastUpdate, Protocol, BlockMNRatio)"
                         ." VALUES ".implode(',',$bhsql)
              ." ON DUPLICATE KEY UPDATE BlockMNPayee = VALUES(BlockMNPayee), LastUpdate = VALUES(LastUpdate), Protocol = VALUES(Protocol), BlockMNRatio = VALUES(BlockMNRatio)";

        if ($result = $mysqli->query($sql)) {
          $bhinfo = $mysqli->info;
          if (is_null($bhinfo)) {
            $bhinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }
        if ($curratio[0] > -1) {
          $stats[] = sprintf("('mnpaymentratio','%s',%d,'dashninja')",$curratio[0],time());
        }
        if ($curratio[1] > -1) {
          $stats[] = sprintf("('mnpaymentratiotest','%s',%d,'dashninja')",$curratio[1],time());
        }
      }

      $bisql = array();
      $bsbsql = array();
      $mninfo = array();
      $sqlwheretemplate = "(BlockHeight = %d AND BlockTestNet = %d)";
      $sqlwhere = array();
      foreach($payload['blocksinfo'] as $bientry) {
        $sqlwhere[] = sprintf($sqlwheretemplate,$bientry['BlockId'],$bientry['BlockTestNet']);
      }
      $sql = <<<EOT
DROP TABLE IF EXISTS _cibh_nodecount;
CREATE TEMPORARY TABLE IF NOT EXISTS
    _cibh_nodecount ENGINE=MEMORY AS (
                        SELECT
                                MP.BlockHeight BlockHeight,
                                BlockMNPayee,
                                COUNT(NodeID) CountNode,
                                MAX(BlockMNRatio) BlockMNRatio
                        FROM
                                (SELECT
                                        BlockHeight,
                                        MAX(Protocol) Protocol
                                FROM
                                        cmd_info_blocks_history2
                                WHERE
					%s
                                GROUP BY
                                        BlockHeight
                                ) MP
                        LEFT JOIN
                                cmd_info_blocks_history2 cibh
                                ON
                                        (cibh.BlockHeight=MP.BlockHeight
                                        AND cibh.Protocol=MP.Protocol)
                                GROUP BY
                                        BlockHeight,
                                        BlockMNPayee
                        );
DROP TABLE IF EXISTS _cibh_maxnodecount;
CREATE TEMPORARY TABLE IF NOT EXISTS _cibh_maxnodecount ENGINE=MEMORY AS (
        SELECT
                BlockHeight,
                MAX(CountNode) MaxCountNode
        FROM
                _cibh_nodecount
        GROUP BY
                BlockHeight
        );
SELECT NC.BlockHeight BlockHeight, BlockMNPayee, BlockMNRatio FROM _cibh_maxnodecount MNC, _cibh_nodecount NC WHERE MNC.BlockHeight = NC.BlockHeight AND MNC.MaxCountNode = NC.CountNode;
EOT;

        $sql = sprintf($sql,implode(" OR ",$sqlwhere));
        $blockhist = array();
        if ($mysqli->multi_query($sql) &&
            $mysqli->more_results() && $mysqli->next_result() &&
            $mysqli->more_results() && $mysqli->next_result() &&
            $mysqli->more_results() && $mysqli->next_result() &&
            $mysqli->more_results() && $mysqli->next_result() &&
            ($result = $mysqli->store_result())) {
          while($row = $result->fetch_assoc()){
            $blockhist[intval($row['BlockHeight'])] = array("BlockMNValueRatioExpected" => floatval($row['BlockMNRatio']),
                                                            "BlockMNPayeeExpected" => $row['BlockMNPayee']);
          }
        }

      foreach($payload['blocksinfo'] as $bientry) {
          // Force actual 50% is value is 0% by mistake (block history is wrong, node was down at that time probably...)
          if ($blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected'] <= 0) {
              $blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected'] = 0.5;
          }

        $bisql[] = sprintf("(%d,%d,'%s','%s',%.9f,%.9f,%d,'%s',%d,%d,%.9f,%d,'%s',%.9f,%d,'%s',%d,%d,%d,%.9f,%d)",$bientry['BlockTestNet'],
                                                     $bientry['BlockId'],
                                                     $mysqli->real_escape_string($bientry['BlockHash']),
                                                     $mysqli->real_escape_string($bientry['BlockMNPayee']),
                                                     $bientry['BlockMNValue'],
                                                     $bientry['BlockSupplyValue'],
                                                     $bientry['BlockMNPayed'],
                                                     $mysqli->real_escape_string($bientry['BlockPoolPubKey']),
                                                     $bientry['BlockMNProtocol'],
                                                     $bientry['BlockTime'],
                                                     $bientry['BlockDifficulty'],
                                                     $bientry['BlockMNPayeeDonation'],
                                                     $mysqli->real_escape_string($blockhist[intval($bientry['BlockId'])]['BlockMNPayeeExpected']),
                                                     $blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected'],
            $bientry['IsSuperblock'],
            $mysqli->real_escape_string($bientry['SuperblockBudgetName']),
            $bientry['BlockDarkSendTXCount'],
            $bientry['MemPoolDarkSendTXCount'],
            $bientry['SuperblockBudgetPayees'],
            $bientry['SuperblockBudgetAmount'],
            $bientry['BlockVersion']
        );
        if ((array_key_exists($bientry['BlockMNPayee'].":".$bientry['BlockTestNet'],$mninfo) && ($mninfo[$bientry['BlockMNPayee'].":".$bientry['BlockTestNet']] < $bientry['BlockId']))
         || !(array_key_exists($bientry['BlockMNPayee'].":".$bientry['BlockTestNet'],$mninfo))) {
          $mninfo[$bientry['BlockMNPayee'].":".$bientry['BlockTestNet']] = $bientry['BlockId'];
        }
        if (array_key_exists("SuperblockDetails",$bientry) && (is_array($bientry["SuperblockDetails"])) && (count($bientry["SuperblockDetails"]) > 0)) {
            foreach($bientry["SuperblockDetails"] as $item) {
                $bsbsql[] = sprintf("(%d,%d,'%s',%.9f,'%s')",$bientry['BlockTestNet'],
                    $bientry['BlockId'],
                    $mysqli->real_escape_string($item['GovernanceObjectPaymentAddress']),
                    floatval($item['GovernanceObjectPaymentAmount']),
                    $mysqli->real_escape_string($item['GovernanceObjectPaymentProposalHash']));
            }
        }
      }
      $mninfosql = array();
      foreach($mninfo as $rawkey => $mnblock) {
        $mnkey = explode(":",$rawkey);
        $mninfosql[] = sprintf("(%d,'%s',%d)",$mnkey[1],
                                              $mysqli->real_escape_string($mnkey[0]),
                                              $mnblock);
      }
      $biinfo = false;
      $mninfoinfo = false;
      if (count($bisql) > 0) {
        $sql = "INSERT INTO cmd_info_blocks (BlockTestNet, BlockId, BlockHash, BlockMNPayee, BlockMNValue, BlockSupplyValue, BlockMNPayed, "
              ."BlockPoolPubKey, BlockMNProtocol, BlockTime, BlockDifficulty, BlockMNPayeeDonation, BlockMNPayeeExpected, BlockMNValueRatioExpected, IsSuperblock, SuperblockBudgetName, "
              ."BlockDarkSendTXCount, MemPoolDarkSendTXCount, SuperblockBudgetPayees, SuperblockBudgetAmount, BlockVersion)"
              ." VALUES ".implode(',',$bisql)
              ." ON DUPLICATE KEY UPDATE BlockHash = VALUES(BlockHash), BlockMNPayee = VALUES(BlockMNPayee), BlockMNValue = VALUES(BlockMNValue),"
              ." BlockSupplyValue = VALUES(BlockSupplyValue), BlockMNPayed = VALUES(BlockMNPayed), BlockPoolPubKey = VALUES(BlockPoolPubKey),"
              ." BlockMNProtocol = VALUES(BlockMNProtocol), BlockTime = VALUES(BlockTime), BlockDifficulty = VALUES(BlockDifficulty),"
              ." BlockMNPayeeDonation = VALUES(BlockMNPayeeDonation), BlockMNPayeeExpected = VALUES(BlockMNPayeeExpected),"
              ." BlockMNValueRatioExpected = VALUES(BlockMNValueRatioExpected), IsSuperblock = VALUES(IsSuperblock), SuperblockBudgetName = VALUES(SuperblockBudgetName),"
              ." BlockDarkSendTXCount = VALUES(BlockDarkSendTXCount), MemPoolDarkSendTXCount = VALUES(MemPoolDarkSendTXCount),"
              ." SuperblockBudgetPayees = VALUES(SuperblockBudgetPayees), SuperblockBudgetAmount = VALUES(SuperblockBudgetAmount),"
              ." BlockVersion = VALUES(BlockVersion)";

        if ($result = $mysqli->query($sql)) {
          $biinfo = $mysqli->info;
          if (is_null($biinfo)) {
            $biinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }
        $mninfores = 0;
        $debugtxt = "";
        $sql = "INSERT INTO cmd_info_masternode_lastpaid (MNTestNet, MNPubKey, MNLastPaidBlock) VALUES ".implode(',',$mninfosql)
               ." ON DUPLICATE KEY UPDATE MNLastPaidBlock = VALUES(MNLastPaidBlock)";
        if ($result = $mysqli->query($sql)) {
          $mninfoinfo = $mysqli->info;
          if (is_null($biinfo)) {
            $mninfoinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }

        $interval = new DateInterval('P1D');
        $interval->invert = 1;
        $datefrom = new DateTime();
        $datefrom->add( $interval );
        $datefrom = $datefrom->getTimestamp();

        $sql = sprintf("SELECT `BlockTestNet`, SUM(`BlockSupplyValue`) TotalSupplyValue, SUM(`BlockMNValue`) TotalMNValue, COUNT(1) NumBlocks, SUM(BlockMNPayed) NumPayed FROM `cmd_info_blocks` WHERE BlockTime >= %d GROUP BY `BlockTestNet`",$datefrom);
        if ($result = $mysqli->query($sql)) {
          while($row = $result->fetch_assoc()){
            $statkey = "last24hsupply";
            if ($row["BlockTestNet"] == 1) {
              $statkey .= "test";
            }
            $stats[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$row["TotalSupplyValue"],time());
            $statkey = "paymentdrk";
            if ($row["BlockTestNet"] == 1) {
              $statkey .= "test";
            }
            $stats[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$row["TotalMNValue"],time());
            $statkey = "mnpayments";
            if ($row["BlockTestNet"] == 1) {
              $statkey .= "test";
            }
            $stats[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,round(($row["NumPayed"]/$row["NumBlocks"])*100,2),time());
          }
        }
      }

      if (count($stats) > 0) {
        $sql = "INSERT INTO cmd_stats_values (StatKey, StatValue, LastUpdate, Source)"
             ." VALUES ".implode(',',$stats)
             ." ON DUPLICATE KEY UPDATE StatValue = VALUES(StatValue), LastUpdate = VALUES(LastUpdate), Source = VALUES(Source)";

        if ($result = $mysqli->query($sql)) {
          $statsinfo = $mysqli->info;
          if (is_null($biinfo)) {
            $statsinfo = true;
          }
        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
          return $response;
        }
      }

      $superblockinfo = false;
      if (count($bsbsql) > 0) {
          $sql = "INSERT INTO cmd_info_blocks_superblockpayments (BlockTestNet, BlockId, GovernanceObjectPaymentAddress, GovernanceObjectPaymentAmount, GovernanceObjectPaymentProposalHash)"
              . " VALUES " . implode(',', $bsbsql)
              . " ON DUPLICATE KEY UPDATE GovernanceObjectPaymentAddress = VALUES(GovernanceObjectPaymentAddress), GovernanceObjectPaymentAmount = VALUES(GovernanceObjectPaymentAmount)";

          if ($result = $mysqli->query($sql)) {
              $superblockinfo = $mysqli->info;
              if (is_null($biinfo)) {
                  $superblockinfo = true;
              }
          } else {
              $response->setStatusCode(503, "Service Unavailable");
              $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno . ': ' . $mysqli->error)));
              return $response;
          }
      }

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('blockshistory' => $bhinfo,
                                                                        'blocksinfo' => $biinfo,
                                                                        'superblockdetailsinfo' => $superblockinfo,
                                                                        'mninfo' => $mninfoinfo)));

    }
  }
  return $response;

});

// ============================================================================
// BUDGETS EXPECTED (for dmnblockparser)
// ----------------------------------------------------------------------------
// End-point to retrieve all expected superblocks
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/budgetsexpected', function() use ($app,&$mysqli) {

    //Create a response
    $response = new Phalcon\Http\Response();

    if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
        //Change the HTTP status
        $response->setStatusCode(400, "Bad Request");
        //Send errors to the client
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
    }
    else {
        // Retrieve all known final budgets
        $sql = 'SELECT BudgetTestnet, BlockStart, BlockEnd, Proposals FROM cmd_budget_final WHERE VoteCount > 0 AND (IsValid = 1 OR IsValidReason = "Older than current blockHeight") AND Status = "OK"';
        $mnbudgets = array(array(),array());
        $proposalsfinal = array(array(),array());
        if ($result = $mysqli->query($sql)) {
            while($row = $result->fetch_assoc()){
                $pos = 0;
                $proposals = explode(",",$row['Proposals']);
                for ($x = intval($row['BlockStart']);$x <= intval($row['BlockEnd']); $x++) {
                    $mnbudgets[$row['BudgetTestnet']][$x] = array(
                        "BlockId" => $x,
                        "BlockProposal" => $proposals[$pos]
                    );
                    $proposalsfinal[$row['BudgetTestnet']][] = $proposals[$pos];
                    $pos++;
                }
            }

            $proposalsvalues = array(array(),array());
            $sql = "SELECT BudgetTestnet, BudgetId, MonthlyPayment, PaymentAddress FROM cmd_budget_projection";
            if ($result = $mysqli->query($sql)) {
                $test = array();
                while ($row = $result->fetch_assoc()) {
                    $test[] = $row;
                    if (in_array($row['BudgetId'], $proposalsfinal[$row['BudgetTestnet']])) {
                        $proposalsvalues[$row['BudgetTestnet']][$row['BudgetId']] = $row;
                    }
                }

                foreach ($mnbudgets as $mnbudgetestnet => $mnbudgetdata) {
                    foreach ($mnbudgetdata as $mnbudgetdataid => $mnbudgetdatadata) {
                        if (array_key_exists($mnbudgetdatadata["BlockProposal"], $proposalsvalues[$mnbudgetestnet])) {
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["MonthlyPayment"] = $proposalsvalues[$mnbudgetestnet][$mnbudgetdatadata["BlockProposal"]]["MonthlyPayment"];
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["PaymentAddress"] = $proposalsvalues[$mnbudgetestnet][$mnbudgetdatadata["BlockProposal"]]["PaymentAddress"];
                        } else {
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["MonthlyPayment"] = 0.0;
                            $mnbudgets[$mnbudgetestnet][$mnbudgetdataid]["PaymentAddress"] = "";
                        };
                    }
                }

                //Change the HTTP status
                $response->setStatusCode(200, "OK");
                $response->setJsonContent(array('status' => 'OK', 'data' => array('budgetsexpected' => $mnbudgets)));
            }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno . ': ' . $mysqli->error)));

        }
        }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        }
    }
    return $response;

});

// ============================================================================
// SUPERBLOCK PAYMENTS EXPECTED (for dmnblockparser)
// ----------------------------------------------------------------------------
// End-point to retrieve all expected superblocks payments (v12.1+)
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/superblocksexpected', function() use ($app,&$mysqli) {

    //Create a response
    $response = new Phalcon\Http\Response();

    if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
        //Change the HTTP status
        $response->setStatusCode(400, "Bad Request");
        //Send errors to the client
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
    }
    else {
        // Retrieve all known final budgets
        $sql = 'SELECT cgot.GovernanceObjectTestnet TestNet, cgot.GovernanceObjectEventBlockHeight BlockHeight, cgotp.GovernanceObjectPaymentAddress '
              .'ProposalPaymentAddress, cgotp.GovernanceObjectPaymentAmount ProposalPaymentAmount, cgotp.GovernanceObjectPaymentProposalHash '
              .'ProposalHash FROM cmd_gobject_triggers cgot LEFT OUTER JOIN cmd_gobject_triggers_payments cgotp '
              .'ON cgot.GovernanceObjectTestnet = cgotp.GovernanceObjectTestnet AND cgot.GovernanceObjectId = cgotp.GovernanceObjectId '
              .'WHERE cgot.GovernanceObjectVotesAbsoluteYes > 0 AND cgot.GovernanceObjectCachedFunding = 1';
        $mnsuperblocks = array(array(),array());
        if ($result = $mysqli->query($sql)) {
            while($row = $result->fetch_assoc()){
                $row["TestNet"] = intval($row["TestNet"]);
                $row["BlockHeight"] = intval($row["BlockHeight"]);
                if (array_key_exists($row['BlockHeight'],$mnsuperblocks[$row["TestNet"]])) {
                    $mnsuperblocks[$row["TestNet"]][$row["BlockHeight"]]["ProposalPayments"][] = array(
                            "ProposalPaymentAddress" => $row["ProposalPaymentAddress"],
                            "ProposalPaymentAmount" => $row["ProposalPaymentAmount"],
                            "ProposalHash" => $row["ProposalHash"]
                    );
                }
                else {
                    $mnsuperblocks[$row["TestNet"]][$row["BlockHeight"]] = array(
                      "BlockHeight" => $row["BlockHeight"],
                      "ProposalPayments" => array(array(
                          "ProposalPaymentAddress" => $row["ProposalPaymentAddress"],
                          "ProposalPaymentAmount" => $row["ProposalPaymentAmount"],
                          "ProposalHash" => $row["ProposalHash"]
                      ))
                    );
                }
            }

            //Change the HTTP status
            $response->setStatusCode(200, "OK");
            $response->setJsonContent(array('status' => 'OK', 'data' => array('superblocksexpected' => $mnsuperblocks)));
        }
        else {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        }
    }
    return $response;

});

// Function to retrieve the masternode list
function dashninja_masternodes_get($mysqli, $testnet = 0, $protocol = 0) {

  $sqlmaxprotocol = sprintf("SELECT MAX(NodeProtocol) Protocol FROM cmd_nodes cn, cmd_nodes_status cns WHERE cn.NodeId = cns.NodeId AND NodeTestnet = %d GROUP BY NodeTestnet",$testnet);
  // Run the query
  if ($result = $mysqli->query($sqlmaxprotocol)) {
    $row = $result->fetch_assoc();
    $protocol = 0;
    if ($row !== false) {
      $protocol = $row['Protocol'];
    }
  }
  else {
    $response->setStatusCode(503, "Service Unavailable");
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    return $response;
  }

  $sqlprotocol = sprintf(" AND cns.NodeProtocol = %d",$protocol);
  $sqltestnet = sprintf("MNTestNet = %d",$testnet);

  // Retrieve the number of time each masternode is seen as active or current
  $sqlactive = "(SELECT MasternodeIP, MasternodePort, MNTestNet, COUNT(1) ActiveCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns"
              ." WHERE ciml.NodeID = cns.NodeID"
              ." AND $sqltestnet"
              ." AND (MasternodeStatus = 'active' OR MasternodeStatus = 'current')"
              .$sqlprotocol
              ." GROUP BY MasternodeIP, MasternodePort, MNTestNet) mnactive";

  // Retrieve the number of time each masternode is seen as inactive
  $sqlinactive = "(SELECT MasternodeIP, MasternodePort, MNTestNet, COUNT(1) InactiveCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns"
              ." WHERE ciml.NodeID = cns.NodeID"
              ." AND $sqltestnet"
              ." AND MasternodeStatus = 'inactive'"
              .$sqlprotocol
              ." GROUP BY MasternodeIP, MasternodePort, MNTestNet) mninactive";

  // Retrieve the number of time each masternode is not seen (unlisted)
  $sqlunlisted = "(SELECT MasternodeIP, MasternodePort, MNTestNet, COUNT(1) UnlistedCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns"
              ." WHERE ciml.NodeID = cns.NodeID"
              ." AND $sqltestnet"
              ." AND MasternodeStatus = 'unlisted'"
              .$sqlprotocol
              ." GROUP BY MasternodeIP, MasternodePort, MNTestNet) mnunlisted";

  // Retrieve only the masternodes which are active or inactive (no need for fully unlisted)
  $sql = "SELECT inet_ntoa(cim.MasternodeIP) MasternodeIP, cim.MasternodePort MasternodePort, cim.MNTestNet MNTestNet, cimpk.MNPubKey MNPubKey FROM cmd_info_masternode cim, cmd_info_masternode_pubkeys cimpk"
        ." LEFT JOIN $sqlactive USING (MasternodeIP, MasternodePort, MNTestNet)"
        ." LEFT JOIN $sqlinactive USING (MasternodeIP, MasternodePort, MNTestNet)"
        ." LEFT JOIN $sqlunlisted USING (MasternodeIP, MasternodePort, MNTestNet)"
        ." WHERE cim.MasternodeIP = cimpk.MasternodeIP AND cim.MasternodePort = cimpk.MasternodePort AND cim.MNTestNet = cimpk.MNTestNet AND cim.$sqltestnet AND ((ActiveCount > 0) OR (InactiveCount > 0)) AND cimpk.MNLastReported = 1";

  // Execute the query
  $numnodes = 0;
  if ($result = $mysqli->query($sql)) {
    $nodes = array();
    while($row = $result->fetch_assoc()){
      $numnodes++;
      $nodes[] = $row;
    }
  }
  else {
    $nodes = false;
  }

  return $nodes;
}

// Function to retrieve the masternode list
function dmn_masternodes2_get($mysqli, $testnet = 0, $protocol = 0, $mnpubkeys = array(), $mnips = array(), $mnvins = array()) {

    $sqlprotocol = sprintf("%d",$protocol);
    $sqltestnet = sprintf("%d",$testnet);

        // Add selection by pubkey
        $sqlpks = "";
        if (count($mnpubkeys) > 0) {
            $sqls = '';
            foreach($mnpubkeys as $mnpubkey) {
                if (strlen($sqls)>0) {
                    $sqls .= ' OR ';
                }
                $sqls .= sprintf("cim.MasternodePubkey = '%s'",$mysqli->real_escape_string($mnpubkey));
            }
            $sqlpks = " AND (".$sqls.")";
        }

        // Add selection by IP:port
        $sqlips = "";
        if (count($mnips) > 0) {
            $sqls = '';
            foreach($mnips as $mnip) {
                if (strlen($sqls)>0) {
                    $sqls .= ' OR ';
                }
                $sqls .= sprintf("(cim.MasternodeIPv6 = INET6_ATON('%s') AND cim.MasternodePort = %d)",$mysqli->real_escape_string($mnip[0]),$mnip[1]);
            }
            $sqlips = " AND (".$sqls.")";
        }

        // Add selection by Output-Index
        $sqlvins = "";
        if (count($mnvins) > 0) {
            $sqls = '';
            foreach($mnvins as $mnvin) {
                $mnoutput = explode('-',$mnvin);
                if (strlen($sqls)>0) {
                    $sqls .= ' OR ';
                }
                $sqls .= sprintf("(cim.MasternodeOutputHash = '%s' AND cim.MasternodeOutputIndex = %d)",$mysqli->real_escape_string($mnoutput[0]),$mnoutput[1]);
            }
            $sqlvins = " AND (".$sqls.")";
        }

        $sql = <<<EOT
SELECT
    cim.MasternodeOutputHash MasternodeOutputHash,
    cim.MasternodeOutputIndex MasternodeOutputIndex,
    inet6_ntoa(cim.MasternodeIPv6) AS MasternodeIP,
    cim.MasternodeTor MasternodeTor,
    cim.MasternodePort MasternodePort,
    cim.MasternodePubkey MasternodePubkey,
    cim.MasternodeProtocol MasternodeProtocol,
    MasternodeLastSeen,
    MasternodeActiveSeconds,
    MasternodeLastPaid,
    ActiveCount,
    InactiveCount,
    UnlistedCount,
    cimlp.MNLastPaidBlock MasternodeLastPaidBlockHeight,
    cib.BlockTime MasternodeLastPaidBlockTime,
    cib.BlockMNValue MasternodeLastPaidBlockAmount
FROM
    (cmd_info_masternode2 cim,
    cmd_info_masternode_active cima)
    LEFT JOIN
        cmd_info_masternode_lastpaid cimlp
            ON (cimlp.MNTestNet = cim.MasternodeTestNet AND cimlp.MNPubKey = cim.MasternodePubkey)
    LEFT JOIN
        cmd_info_blocks cib
            ON (cib.BlockTestNet = cimlp.MNTestNet AND cib.BlockId = cimlp.MNLastPaidBlock)
WHERE
    cim.MasternodeOutputHash = cima.MasternodeOutputHash AND
    cim.MasternodeOutputIndex = cima.MasternodeOutputIndex AND
    cim.MasternodeTestNet = cima.MasternodeTestNet AND
    cim.MasternodeTestNet = $sqltestnet AND
    cima.MasternodeProtocol = $sqlprotocol AND
    ((ActiveCount > 0) OR (InactiveCount > 0))$sqlpks$sqlips$sqlvins
ORDER BY MasternodeOutputHash, MasternodeOutputIndex;
EOT;

        // Execute the query
        $numnodes = 0;
        if ($result = $mysqli->query($sql)) {
            $nodes = array();
            while($row = $result->fetch_assoc()){
                $numnodes++;
                if (is_null($row['ActiveCount'])) {
                    $row['ActiveCount'] = 0;
                }
                else {
                    $row['ActiveCount'] = intval($row['ActiveCount']);
                }
                if (is_null($row['InactiveCount'])) {
                    $row['InactiveCount'] = 0;
                }
                else {
                    $row['InactiveCount'] = intval($row['InactiveCount']);
                }
                if (is_null($row['UnlistedCount'])) {
                    $row['UnlistedCount'] = 0;
                }
                else {
                    $row['UnlistedCount'] = intval($row['UnlistedCount']);
                }
                if (strlen($row['MasternodeLastSeen']) == 16) {
                    $row['MasternodeLastSeen'] = substr($row['MasternodeLastSeen'],0,-6);
                }
                if (!is_null($row['MasternodeLastPaidBlockHeight'])) {
                    $row['LastPaidFromBlocks'] = array("MNLastPaidBlock" => $row['MasternodeLastPaidBlockHeight'],
                        "MNLastPaidTime" => $row['MasternodeLastPaidBlockTime'],
                        "MNLastPaidAmount" => $row['MasternodeLastPaidBlockAmount']);
                }
                else {
                    $row['LastPaidFromBlocks'] = false;
                }
                unset($row['MasternodeLastPaidBlockHeight'],$row['MasternodeLastPaidBlockTime'],$row['MasternodeLastPaidBlockAmount']);
                $nodes[] = $row;
            }
        }
        else {
            $nodes = false;
        }

    return $nodes;
}

// Function to retrieve the masternode count
function dmn_masternodes_count($mysqli, $testnet, &$totalmncount, &$uniquemnips) {

    $protocols = array();
        $sqlprotocols = sprintf("SELECT NodeProtocol FROM cmd_nodes cn, cmd_nodes_status cns WHERE cn.NodeId = cns.NodeId AND NodeTestnet = %d GROUP BY NodeProtocol",$testnet);
        // Run the query
        $result = $mysqli->query($sqlprotocols);
        while ($row = $result->fetch_assoc()) {
            $protocols[] = intval($row['NodeProtocol']);
        }
    $maxprotocol = 0;
    $mninfo = array();

    foreach ($protocols as $protocol) {
        $mninfo[$protocol] = array("ActiveMasternodesUniqueIPs" => array(),
            "ActiveMasternodesCount" => 0);
        if ($protocol > $maxprotocol) {
            $maxprotocol = $protocol;
        }
    }

    $uniquemnips = 0;
    $totalmncount = 0;

    foreach ($protocols as $protocol) {
        $fulllist = dmn_masternodes2_get($mysqli, $testnet, $protocol);

        $mninfo[$protocol]["ActiveMasternodesCount"] = 0;

        foreach ($fulllist as $masternode) {
            if ($masternode["ActiveCount"] > 0) {
                if (!in_array($masternode["MasternodeIP"], $mninfo[$protocol]["ActiveMasternodesUniqueIPs"])) {
                    $mninfo[$protocol]["ActiveMasternodesUniqueIPs"][] = $masternode["MasternodeIP"];
                }
                $mninfo[$protocol]["ActiveMasternodesCount"]++;
            }
        }
        if ($protocol == $maxprotocol) {
            $totalmncount = $mninfo[$protocol]["ActiveMasternodesCount"];
        }
    }
    foreach ($mninfo as $protocol => $mn) {
        $mninfo[$protocol]["ActiveMasternodesUniqueIPs"] = count($mninfo[$protocol]["ActiveMasternodesUniqueIPs"]);
    }

    $uniquemnips = $mninfo[$maxprotocol]["ActiveMasternodesUniqueIPs"];

    return $mninfo;

}

function drkmn_masternodes_count($mysqli,$testnet,&$totalmncount,&$uniquemnips) {

    // Retrieve the total unique IPs per protocol version
/*    $sqlmnnum1 = sprintf("(SELECT first.Protocol Protocol, COUNT(1) UniqueActiveMasternodesIPs FROM "
                       ."(SELECT ciml.MasternodeIP MNIP, ciml.MasternodePort MNPort, cns.NodeProtocol Protocol, COUNT(1) ActiveCount FROM cmd_info_masternode_list ciml, cmd_nodes_status cns, cmd_nodes cmn WHERE"
                       ." ciml.NodeID = cns.NodeID AND ciml.NodeID = cmn.NodeID AND cmn.NodeEnabled = 1 AND ciml.MNTestNet = %d"
                       ." AND cns.NodeProcessStatus = 'running' AND (ciml.MasternodeStatus = 'active' OR ciml.MasternodeStatus = 'current')"
                       ." GROUP BY ciml.MasternodeIP, ciml.MasternodePort, cns.NodeProtocol) first GROUP BY first.Protocol) a",$testnet);
*/

    $sqlmnnum1 = sprintf("(SELECT first.Protocol Protocol, COUNT(1) UniqueActiveMasternodesIPs FROM "
                       ."(SELECT cim.MasternodeIP MNIP, cim.MasternodePort MNPort, cim.MasternodeProtocol Protocol, COUNT(1) ActiveCount"
                       ." FROM cmd_info_masternode2_list ciml, cmd_nodes_status cns, cmd_nodes cmn, cmd_info_masternode2 cim WHERE"
                       ." ciml.MasternodeOutputHash = cim.MasternodeOutputHash AND ciml.MasternodeOutputIndex = cim.MasternodeOutputIndex AND "
                       ." cns.NodeID AND ciml.NodeID = cmn.NodeID AND cmn.NodeEnabled = 1 AND ciml.MasternodeTestNet = %d AND "
                       ." ciml.NodeID = cns.NodeID AND ciml.NodeID = cmn.NodeID AND cmn.NodeEnabled = 1"
                       ." AND cns.NodeProcessStatus = 'running' AND (ciml.MasternodeStatus = 'active' OR ciml.MasternodeStatus = 'current')"
                       ." GROUP BY cim.MasternodeIP, cim.MasternodePort, cim.MasternodeProtocol) first GROUP BY first.Protocol) a",$testnet);


    // Retrieve the total masternodes per protocol version
/*    $sqlmnnum2 = sprintf("(SELECT second.Protocol Protocol, COUNT(1) ActiveMasternodesCount FROM "
                       ."(SELECT ciml.MasternodeIP MNIP, ciml.MasternodePort MNPort, cimpk.MNPubKey MNPubkey, cns.NodeProtocol Protocol, COUNT(1) ActiveCount FROM cmd_info_masternode_list ciml,"
                       ." cmd_info_masternode_pubkeys cimpk, cmd_nodes_status cns, cmd_nodes cmn WHERE"
                       ." ciml.MasternodeIP = cimpk.MasternodeIP AND ciml.MasternodePort = cimpk.MasternodePort AND ciml.MNTestNet = cimpk.MNTestNet AND cimpk.MNLastReported = 1 AND"
                       ." ciml.NodeID = cns.NodeID AND ciml.NodeID = cmn.NodeID AND cmn.NodeEnabled = 1 AND ciml.MNTestNet = %d AND cns.NodeProcessStatus = 'running' AND"
                       ." (ciml.MasternodeStatus = 'active' OR ciml.MasternodeStatus = 'current')"
                       ." GROUP BY ciml.MasternodeIP, ciml.MasternodePort, cimpk.MNPubKey, cns.NodeProtocol) second GROUP BY second.Protocol) b",$testnet);
*/
    $sqlmnnum2 = sprintf("(SELECT second.Protocol Protocol, COUNT(1) ActiveMasternodesCount FROM "
                       ."(SELECT cim.MasternodeIP MNIP, cim.MasternodePort MNPort, cim.MasternodeOutputHash MNOutHash, cim.MasternodeOutputIndex MNOutIndex,"
                       ." cim.MasternodeProtocol Protocol, COUNT(1) ActiveCount FROM cmd_info_masternode2_list ciml,"
                       ." cmd_info_masternode2 cim, cmd_nodes_status cns, cmd_nodes cmn WHERE"
                       ." ciml.MasternodeOutputHash = cim.MasternodeOutputHash AND ciml.MasternodeOutputIndex = cim.MasternodeOutputIndex AND ciml.MasternodeTestNet = cim.MasternodeTestNet AND"
                       ." ciml.NodeID = cns.NodeID AND ciml.NodeID = cmn.NodeID AND cmn.NodeEnabled = 1 AND ciml.MasternodeTestNet = %d AND cns.NodeProcessStatus = 'running' AND"
                       ." (ciml.MasternodeStatus = 'active' OR ciml.MasternodeStatus = 'current')"
                       ." GROUP BY cim.MasternodeIP, cim.MasternodePort, cim.MasternodeOutputHash, cim.MasternodeOutputIndex, cim.MasternodeProtocol) second GROUP BY second.Protocol) b",$testnet);

    $sqlmnnum = "SELECT a.Protocol, a.UniqueActiveMasternodesIPs UniqueActiveMasternodesIPs, b.ActiveMasternodesCount ActiveMasternodesCount FROM $sqlmnnum1, $sqlmnnum2 WHERE a.Protocol = b.Protocol";

  $totalmncount = 0;
  $uniquemnips = 0;
  // Run the queries
  if ($result = $mysqli->query($sqlmnnum)) {
    $mninfo = array();
    $curprotocol = 0;
    // Group the result by masternode ip:port (status is per protocolversion and nodename)
    while($row = $result->fetch_assoc()){
      $mninfo[$row['Protocol']] = array("UniqueActiveMasternodesIPs" => $row['UniqueActiveMasternodesIPs'],
                                        "ActiveMasternodesCount" => $row['ActiveMasternodesCount']);
      if ($curprotocol < $row['Protocol']) {
        $curprotocol = $row['Protocol'];
      }
      $uniquemnips += $row['UniqueActiveMasternodesIPs'];
      $totalmncount += $row['ActiveMasternodesCount'];
    }
  }
  else {
    $mninfo = false;
  }

  return $mninfo;

}

// Function to retrieve the masternode list
function dmn_cmd_masternodes2_get($mysqli, $testnet = 0) {

    $sqltestnet = sprintf("%d",$testnet);

    $sql = <<<EOT
DROP TABLE IF EXISTS _node_status2;
CREATE TEMPORARY TABLE IF NOT EXISTS
    _node_status2 ENGINE=MEMORY AS (
    SELECT
        ciml.MasternodeOutputHash,
        ciml.MasternodeOutputIndex,
        ciml.MasternodeStatus,
        ciml.MasternodeTestNet,
        SUM(CASE
            WHEN MasternodeStatus = 'active' THEN 1
            WHEN MasternodeStatus = 'current' THEN 1
            ELSE NULL END) AS ActiveCount,
        SUM(CASE
            WHEN MasternodeStatus = 'inactive' THEN 1
            ELSE NULL END) AS InactiveCount,
        SUM(CASE
            WHEN MasternodeStatus = 'unlisted' THEN 1
            ELSE NULL END) AS UnlistedCount
    FROM
        cmd_info_masternode2_list ciml, cmd_nodes_status cns
    WHERE
        ciml.NodeID = cns.NodeID AND
        ciml.MasternodeTestNet = $sqltestnet
    GROUP BY
        ciml.MasternodeOutputHash, ciml.MasternodeOutputIndex, ciml.MasternodeTestNet
    );
SELECT
    cim.MasternodeOutputHash MasternodeOutputHash,
    cim.MasternodeOutputIndex MasternodeOutputIndex,
    inet6_ntoa(cim.MasternodeIPv6) AS MasternodeIP,
    cim.MasternodeTor MasternodeTor,
    cim.MasternodePort MasternodePort,
    cim.MasternodePubkey MasternodePubkey,
    MasternodeProtocol
FROM
    (cmd_info_masternode2 cim,
    _node_status2)
WHERE
    cim.MasternodeOutputHash = _node_status2.MasternodeOutputHash AND
    cim.MasternodeOutputIndex = _node_status2.MasternodeOutputIndex AND
    cim.MasternodeTestNet = _node_status2.MasternodeTestNet AND
    cim.MasternodeTestNet = $sqltestnet AND
    ((ActiveCount > 0) OR (InactiveCount > 0))
ORDER BY MasternodeOutputHash, MasternodeOutputIndex;
EOT;

    // Execute the query
    $numnodes = 0;
    if ($mysqli->multi_query($sql)) {
        if ($mysqli->more_results() && $mysqli->next_result()) {
            if ($mysqli->more_results() && $mysqli->next_result()) {
                if ($result = $mysqli->store_result()) {
                    $nodes = array();
                    while($row = $result->fetch_assoc()){
                        $numnodes++;
                        $row["OperadorReward"] = floatval(0.0);
                        $row["OperadorRewardAddress"] = "";
                        $nodes[] = $row;
                    }
                }
                else {
                    $nodes = false;
                }
            }
            else {
                $nodes = false;
            }
        }
        else {
            $nodes = false;
        }
    }
    else {
        $nodes = false;
    }

    return $nodes;
}


// Function to retrieve the deterministic masternode list
function dmn_cmd_protx_get($mysqli, $testnet = 0) {

  $sqltestnet = sprintf("%d",$testnet);

  $sql = <<<EOT
SELECT
    cp.proTxHash proTxHash,
    cp.collateralHash MasternodeOutputHash,
    cp.collateralIndex MasternodeOutputIndex,
    inet6_ntoa(cps.addrIP) MasternodeIP,
    cps.addrPort MasternodePort,
    cps.payoutAddress MasternodePubkey,
    cps.operatorRewardAddress OperatorRewardAddress,
    cp.operatorReward OperatorReward,
    UNIX_TIMESTAMP(cp.LastSeen) lastSeen
FROM
    cmd_protx cp
LEFT JOIN cmd_protx_state cps USING (proTxTestNet, proTxHash)
LEFT JOIN cmd_nodes cn USING (NodeID)
WHERE
    cp.proTxTestNet = $sqltestnet AND (UNIX_TIMESTAMP()-UNIX_TIMESTAMP(cp.LastSeen) <= 3600)
ORDER BY proTxHash;
EOT;

    // Execute the query
    if ($result = $mysqli->query($sql)) {
      $nodestmp = array();
      while($row = $result->fetch_assoc()){
        if ((time() - intval($row["lastSeen"])) > 300) {
          $active = 0;
        }
        else {
          $active = 1;
        }
        if (!array_key_exists($row["proTxHash"],$nodestmp)) {
          $nodestmp[$row["proTxHash"]] = array(
            "MasternodeOutputHash" => $row["MasternodeOutputHash"],
            "MasternodeOutputIndex" => intval($row["MasternodeOutputIndex"]),
            "MasternodeIP" => $row["MasternodeIP"],
            "MasternodeTor" => "",
            "MasternodePort" => intval($row["MasternodePort"]),
            "MasternodePubkey" => $row["MasternodePubkey"],
            "MasternodeProtocol" => 70212,
            "OperatorRewardAddress" => $row["OperatorRewardAddress"],
            "OperatorReward" => floatval($row["OperatorReward"]),
            "activeCount" => $active,
          );
        }
        else {
          $nodestmp[$row["proTxHash"]]["activeCount"] += $active;
        }
      }
      $nodes = array();
      foreach($nodestmp as $node) {
        if ($node["activeCount"] > 0) {
          unset($node["activeCount"]);
          $nodes[] = $node;
        }
      }
    }
    else {
      $nodes = false;
    }

  return $nodes;
}

// ============================================================================
// MASTERNODES
// ----------------------------------------------------------------------------
// End-point to retrieve all masternodes ip, port, testnet and pubkeys
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/masternodes', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  // Retrieve the 'testnet' parameter
  if ($request->hasQuery('testnet')) {
    $testnet = intval($request->getQuery('testnet'));
    if (($testnet != 0) && ($testnet != 1)) {
      $testnet = 0;
    }
  }
  else {
    $testnet = 0;
  }
  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {

    $protxlist = dmn_cmd_protx_get($mysqli, $testnet);;
    $protxlisterrno = $mysqli->errno;
    $protxlisterror = $mysqli->error;
    if ($protxlist !== false) {
      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('masternodes' => $protxlist)));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($protxlisterrno.': '.$protxlisterror,print_r($protxlist,true))));
    }
  }
  return $response;

});

// ============================================================================
// MASTERNODES/DONATIONS
// ----------------------------------------------------------------------------
// End-point to retrieve all masternodes donations pubkeys and max protocol
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/masternodes/donations', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    if ($request->hasQuery('all') && ($request->getQuery('all')==1)) {
      $sql = "SELECT MNPubKey FROM cmd_info_masternode_donation "
            ."GROUP BY MNPubKey ORDER BY MNPubKey";
    }
    else {
      $sql = "SELECT MNPubKey, MAX(NodeProtocol) MaxProtocol FROM cmd_info_masternode_donation mn, cmd_info_masternode_list mnl, cmd_nodes_status ns "
            ."WHERE mn.MasternodeIP = mnl.MasternodeIP "
            ."AND mn.MasternodePort = mnl.MasternodePort "
            ."AND mn.MNTestNet = mnl.MNTestNet "
            ."AND mnl.NodeID = ns.NodeID "
            ."AND (mnl.MasternodeStatus = 'active' OR mnl.MasternodeStatus = 'current') "
            ."AND (mnl.MasternodeStatus = 'active' OR mnl.MasternodeStatus = 'current') "
            ."GROUP BY MNPubKey ORDER BY MNPubKey";
    }

    $mndonations = array();
    if ($result = $mysqli->query($sql)) {
      while($row = $result->fetch_array()){
        $mndonations[$row[0]] = $row[1];
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('mndonations' => $mndonations)));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// MASTERNODES/PUBKEYS
// ----------------------------------------------------------------------------
// End-point to retrieve all masternodes pubkeys and max protocol
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/masternodes/pubkeys', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    if ($request->hasQuery('all') && ($request->getQuery('all')==1)) {
      $sql = "SELECT MasternodePubkey FROM cmd_info_masternode2 "
            ."GROUP BY MasternodePubkey ORDER BY MasternodePubkey";
    }
    else {
      // Retrieve all known nodes for current hub
      $sql = "SELECT MasternodePubkey, MAX(MasternodeProtocol) MaxProtocol FROM cmd_info_masternode2 "
            ."GROUP BY MasternodePubkey ORDER BY MasternodePubkey";
    }

    $mnpubkeys = array();
    if ($result = $mysqli->query($sql)) {
      while($row = $result->fetch_array()){
        $mnpubkeys[$row[0]] = $row[1];
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('mnpubkeys' => $mnpubkeys)));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// NODES
// ----------------------------------------------------------------------------
// End-point to retrieve all known nodes for current hub (as identified by SSL)
// HTTP method:
//   GET
// Parameters:
//   NodeTestnet=1|0 (optional)
//   NodeEnabled=1|0 (optional)
//   NodeType=p2pool|masternode (optional)
// ============================================================================
$app->get('/nodes', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    // Retrieve all known nodes for current hub
    $sql = "SELECT NodeName, NodeTestNet, NodeEnabled, NodeType, VersionPath, VersionRaw, VersionDisplay, VersionHandling, KeepUpToDate, KeepRunning FROM cmd_nodes n, cmd_hub_nodes h, cmd_versions v WHERE n.NodeId = h.NodeId AND n.VersionID = v.VersionID AND h.HubId = %d";
    if ($request->hasQuery('NodeTestnet')) {
      $sql .= sprintf(" AND NodeTestnet = %d",$request->getQuery('NodeTestnet'));
    }
    if ($request->hasQuery('NodeEnabled')) {
      $sql .= sprintf(" AND NodeEnabled = %d",$request->getQuery('NodeEnabled'));
    }
    if ($request->hasQuery('NodeType')) {
      $sql .= sprintf(" AND NodeType = '%s'",$mysqli->real_escape_string($request->getQuery('NodeType')));
    }
    $sqlx = sprintf($sql,$authinfo['HubId']);
    $numnodes = 0;
    $nodes = array();
    if ($result = $mysqli->query($sqlx)) {
      while($row = $result->fetch_assoc()){
        $numnodes++;
        $nodes[$row['NodeName']] = $row;
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => $nodes));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

function dashninja_cmd_getnodes($mysqli,$hubid = -1,$testnet = 0) {

  $cachefnam = CACHEFOLDER.sprintf("dashninja_cmd_getnodes_%d_%d",$hubid,$testnet);
  $cachevalid = (is_readable($cachefnam) && ((filemtime($cachefnam)+3600)>=time()));
  if ($cachevalid) {
    $nodes = unserialize(file_get_contents($cachefnam));
  }
  else {
    $sql = sprintf("SELECT n.NodeId NodeId, NodeName, NodeTestNet, NodeEnabled, NodeType FROM cmd_nodes n, cmd_hub_nodes h WHERE n.NodeId = h.NodeId AND n.NodeTestNet = %d",intval($testnet));
    if ($hubid > -1) {
      $sql = sprintf($sql." AND h.HubId = %d",$hubid);
    }
    $result = $mysqli->query($sql);
    $nodes = array();
    if ($result !== false) {
      while($row = $result->fetch_assoc()){
        $nodes[$row['NodeName']] = $row;
      }
    }
    file_put_contents($cachefnam,serialize($nodes),LOCK_EX);
  }

  return $nodes;

}

// ============================================================================
// PING (Reporting for dmnctl status)
// ----------------------------------------------------------------------------
// End-point for the hubs to report their statuses
// HTTP method:
//   POST
// Parameters (JSON body):
//   nodes=array of node information (mandatory)
//   mninfo=array of masternode information (mandatory)
//   mnlist=array of masternode status (mandatory)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/ping', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !array_key_exists('nodes',$payload) || !array_key_exists('testnet',$payload)
   || !array_key_exists('stats',$payload) || !is_array($payload['stats'])
   || !array_key_exists('mninfo',$payload) || !is_array($payload['mninfo'])
   || !array_key_exists('mninfo2',$payload) || !is_array($payload['mninfo2'])
   || !array_key_exists('mnpubkeys',$payload) || !is_array($payload['mnpubkeys'])
   || !array_key_exists('mnbudgetshow',$payload) || !is_array($payload['mnbudgetshow'])
   || !array_key_exists('mnbudgetprojection',$payload) || !is_array($payload['mnbudgetprojection'])
   || !array_key_exists('mnbudgetfinal',$payload) || !is_array($payload['mnbudgetfinal'])
   || !array_key_exists('mnbudgetvotes',$payload) || !is_array($payload['mnbudgetvotes'])
   || !array_key_exists('gobjproposals',$payload) || !is_array($payload['gobjproposals'])
   || !array_key_exists('gobjtriggers',$payload) || !is_array($payload['gobjtriggers'])
   || !array_key_exists('gobjvotes',$payload) || !is_array($payload['gobjvotes'])
   || !array_key_exists('protx',$payload) || !is_array($payload['protx'])
   || !array_key_exists('mnlist',$payload) || !is_array($payload['mnlist'])
   || !array_key_exists('mnlist2',$payload) || !is_array($payload['mnlist2'])) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {
    // Retrieve all known nodes for current hub
    $istestnet = intval($payload['testnet']);
    $nodes = dashninja_cmd_getnodes($mysqli,$authinfo['HubId'],$istestnet);
    $numnodes = count($nodes);
    if ($numnodes > 0) {
      if ($numnodes == count($payload['nodes'])) {
        $sqlstatus = array();
        $sqlspork = array();
          $sporkprunepernodeid = array();
          $sqlsporksprune = null;

          foreach($payload['nodes'] as $uname => $node) {
              if (!array_key_exists($uname, $nodes)) {
                  $response->setStatusCode(503, "Service Unavailable");
                  $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
                  return $response;
              }
              $sqlstatus[] = sprintf("(%d,'%s',%d,%d,%d,'%s',%d,'%s','%s',NOW())",
                  $nodes[$uname]['NodeId'],
                  $mysqli->real_escape_string($node['ProcessStatus']),
                  $node['Version'],
                  $node['Protocol'],
                  $node['Blocks'],
                  $mysqli->real_escape_string($node['LastBlockHash']),
                  $node['Connections'],
                  $mysqli->real_escape_string($node['Country']),
                  $mysqli->real_escape_string($node['CountryCode'])
              );
              if (array_key_exists("Spork", $node) && is_array($node['Spork'])) {
                  $sporkprunepernodeid[intval($nodes[$uname]['NodeId'])] = array();
                  foreach ($node['Spork'] as $sporkname => $sporkvalue) {
                      $sporknameesc = $mysqli->real_escape_string($sporkname);
                      $sporkprunepernodeid[intval($nodes[$uname]['NodeId'])][] = sprintf('(SporkName <> "%s")', $sporknameesc);
                      $sqlspork[] = sprintf("(%d,'%s',%d)",
                          $nodes[$uname]['NodeId'],
                          $mysqli->real_escape_string($sporknameesc),
                          $sporkvalue
                      );
                  }
              }
          }

          $debugspork = var_export($sporkprunepernodeid,true)."\n";
          $sporksprune = array();
          foreach ($sporkprunepernodeid as $nodeid => $sporks) {
              if (count($sporks) > 0) {
                  $sporksprune[] = sprintf("(NodeID = %d AND ".implode(" AND ",$sporks).")",$nodeid);
              }
              else {
                  $sporksprune[] = sprintf("(NodeID = %d)",$nodeid);
              }
          }
          $sqlsporksprune = "DELETE FROM cmd_nodes_spork WHERE ".implode(" OR ",$sporksprune);
          unset($sporksprune,$sporkprunepernodeid);

        $sql = "INSERT INTO cmd_nodes_status (NodeId, NodeProcessStatus, NodeVersion, NodeProtocol, NodeBlocks, NodeLastBlockHash,"
                                   ." NodeConnections, NodeCountry, NodeCountryCode, LastUpdate)"
                           ." VALUES ".implode(',',$sqlstatus)
            ." ON DUPLICATE KEY UPDATE NodeProcessStatus = VALUES(NodeProcessStatus), NodeVersion = VALUES(NodeVersion),"
            ." NodeProtocol = VALUES(NodeProtocol), NodeBlocks = VALUES(NodeBlocks), NodeLastBlockHash = VALUES(NodeLastBlockHash),"
            ." NodeConnections = VALUES(NodeConnections), NodeCountry = VALUES(NodeCountry),"
            ." NodeCountryCode = VALUES(NodeCountryCode), LastUpdate = NOW()";

        if ($result = $mysqli->query($sql)) {
          $nodesinfo = $mysqli->info;

          $sql = "INSERT INTO cmd_nodes_spork (NodeID, SporkName, SporkValue) VALUE ".implode(',',$sqlspork)
                ." ON DUPLICATE KEY UPDATE SporkValue = VALUES(SporkValue)";
          $result = $mysqli->query($sql);
          $sporkinfo = "Insert: ".$mysqli->info." / Delete: ";

          if (is_null($sqlsporksprune)) {
             $sporkinfo .= "Nothing to prune";
          }
          else {
             $result = $mysqli->query($sqlsporksprune);
             $sporkinfo .= $mysqli->info;
          }

          $mninfosql = array();
          $mnqueryexc = array();
          $sqlpc = array();
          foreach($payload['mninfo'] as $mninfo) {
            $mniplong = ip2long($mninfo['MasternodeIP']);
            if ($mniplong === false) {
              $mniplong = 0;
            }
              $mninfosql[] = sprintf("(%d, %d, %d, %d, %d, '%s', '%s')",
                                     $mniplong,
                                     $mninfo['MasternodePort'],
                                     $mninfo['MNTestNet'],
                                     $mninfo['MNActiveSeconds'],
                                     $mninfo['MNLastSeen'],
                                     $mysqli->real_escape_string($mninfo['MNCountry']),
                                     $mysqli->real_escape_string($mninfo['MNCountryCode'])
                                    );
              $mnqueryexc[] = sprintf("!(MasternodeIP = %d AND MasternodePort = %d AND MNTestNet = %d)",$mniplong,$mninfo['MasternodePort'],$mninfo['MNTestNet']);
              $mngeoip = geoip_record_by_name($mninfo['MasternodeIP']);
              if ($mngeoip !== FALSE) {
                 $mnipcountry = $mngeoip["country_name"];
                 $mnipcountrycode = strtolower($mngeoip["country_code"]);
              }
              else {
                 $mnipcountry = "Unknown";
                 $mnipcountrycode = "__";
              }
              $sqlpc[] = sprintf("(INET6_ATON('%s'), %d, %d, 'unknown', '%s', '%s')",
                  $mysqli->real_escape_string($mninfo['MasternodeIP']),
                  $mninfo['MasternodePort'],
                                     $mninfo['MNTestNet'],
                                     $mnipcountry,
                                     $mnipcountrycode
                                    );

          }

          $mninfoinfo = false;
          if (count($mninfosql) > 0) {
            $sql = "INSERT INTO cmd_info_masternode (MasternodeIP, MasternodePort, MNTestNet,"
                           ." MNActiveSeconds, MNLastSeen, MNCountry, MNCountryCode) VALUES ".implode(',',$mninfosql)
                ." ON DUPLICATE KEY UPDATE MNActiveSeconds = VALUES(MNActiveSeconds),"
                ." MNLastSeen = VALUES(MNLastSeen), MNCountry = VALUES(MNCountry), MNCountryCode = VALUES(MNCountryCode)";

            $result2 = $mysqli->query($sql);
            $mninfoinfo = $mysqli->info;
            unset($mninfosql);
          }

          // VersionHandling 3 (v12)
/*      $wsmninfo2[] = array("MasternodeOutputHash" => $mnoutputhash,
                           "MasternodeOutputIndex" => $mnoutputindex,
                           "MasternodeTestNet" => $mntestnet,
                           "MasternodeProtocol" => $mninfo["MasternodeProtocol"],
                           "MasternodePubkey" => $mninfo["MasternodePubkey"],
                           "MasternodeIP" => $mninfo["MasternodeIP"],
                           "MasternodePort" => $mninfo["MasternodePort"],
                           "MasternodeLastSeen" => $mninfo["MasternodeLastSeen"],
                           "MasternodeActiveSeconds" => $mninfo["MasternodeActiveSeconds"],
                           "MasternodeLastPaid" => $mninfo["MasternodeLastPaid"]);*/
/*          $sql = "SELECT MasternodeOutputHash, MasternodeOutputIndex, MasternodeTestNet FROM cmd_info_masternode2";
          $unlistedmn2 = array();
          if ($result22b = $mysqli->query($sql)) {
            while($row = $result22b->fetch_assoc()){
              $unlistedmn2[] = $row;
            }
          }*/

            $protxsql = array();
            $protxstatesql = array();
            foreach($payload['protx'] as $testnet => $protxlist) {
              foreach($protxlist as $protxhash => $protx) {
                  $protxhash = $mysqli->real_escape_string($protxhash);
                  $protxcollateralhash = $mysqli->real_escape_string($protx['collateralHash']);
                  // ProTx info
                  $protxsql[] = sprintf("(%d, '%s', '%s', %d, %5.2f, %d, NOW())",
                      $testnet,
                      $protxhash,
                      $protxcollateralhash,
                      $protx['collateralIndex'],
                      $protx['operatorReward'],
                      $protx['confirmations']);
                  // ProTx States d
                  foreach ($protx["state"] as $uname => $protxstate) {
                      if (!array_key_exists($uname, $nodes)) {
                          $response->setStatusCode(503, "Service Unavailable");
                          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
                          return $response;
                      }
                      $nodeid = $nodes[$uname]['NodeId'];
                      $keyIDOwner = $mysqli->real_escape_string($protxstate['ownerAddress']);
                      $pubKeyOperator = $mysqli->real_escape_string($protxstate['pubKeyOperator']);
                      $keyIDVoting = $mysqli->real_escape_string($protxstate['votingAddress']);
                      $addr = $mysqli->real_escape_string($protxstate['service']);
                      $payoutAddress = $mysqli->real_escape_string($protxstate['payoutAddress']);
                      if (array_key_exists('operatorRewardAddress',$protxstate)) {
                          $operatorRewardAddress = $mysqli->real_escape_string($protxstate['operatorRewardAddress']);
                      }
                      else {
                          $operatorRewardAddress = "";
                      }

                      $mnip = $mysqli->real_escape_string(substr($addr,0,strrpos($addr,":")));
                      $mnport = intval(substr($addr,0-strlen($addr)+strlen($mnip)+1));

                      $protxstatesql[] = sprintf("(%d, '%s', %d, %d, %d, %d, %d, %d, %d, '%s', '%s', '%s', INET6_ATON('%s'), %d, '%s', '%s')",
                          $testnet,
                          $protxhash,
                          $nodeid,
                          $protxstate['registeredHeight'],
                          $protxstate['lastPaidHeight'],
                          $protxstate['PoSePenalty'],
                          $protxstate['PoSeRevivedHeight'],
                          $protxstate['PoSeBanHeight'],
                          $protxstate['revocationReason'],
                          $keyIDOwner,
                          $pubKeyOperator,
                          $keyIDVoting,
                          $mnip,
                          $mnport,
                          $payoutAddress,
                          $operatorRewardAddress
                      );

                      $mngeoip = geoip_record_by_name($mnip);
                      if ($mngeoip !== FALSE) {
                          $mnipcountry = $mngeoip["country_name"];
                          $mnipcountrycode = strtolower($mngeoip["country_code"]);
                      } else {
                          $mnipcountry = "Unknown";
                          $mnipcountrycode = "__";
                      }
                      $sqlpc[] = sprintf("(INET6_ATON('%s'), %d, %d, 'unknown', '%s', '%s')",
                          $mnip,
                          $mnport,
                          $testnet,
                          $mnipcountry,
                          $mnipcountrycode
                      );
                  }
              }
            }

            if (count($protxsql) > 0) {
                $sql = "INSERT INTO cmd_protx (proTxTestNet, proTxHash, collateralHash, collateralIndex, operatorReward, confirmations, LastSeen) "
                    ." VALUE ".implode(',',$protxsql)
                    ." ON DUPLICATE KEY UPDATE collateralHash = VALUES(collateralHash),"
                    ." collateralIndex = VALUES(collateralIndex), operatorReward = VALUES(operatorReward),"
                    ." confirmations = VALUES(confirmations), LastSeen = VALUES(LastSeen)";

                if ($result91 = $mysqli->query($sql)) {
                    $protxinfo = $mysqli->info;
                }
                else {
                    $protxinfo = $mysqli->error;
                }
                unset($protxsql);
            }
            else {
                $protxinfo = "Nothing to do";
            }

            if (count($protxstatesql) > 0) {
                $sql = "INSERT INTO cmd_protx_state (proTxTestNet, proTxHash, NodeID, registeredHeight, lastPaidHeight,"
                    ." PoSePenalty, PoSeRevivedHeight, PoSeBanHeight, revocationReason, keyIDOwner, pubKeyOperator,"
                    ." keyIDVoting, addrIP, addrPort, payoutAddress, operatorRewardAddress)"
                    ." VALUE ".implode(',',$protxstatesql)
                    ." ON DUPLICATE KEY UPDATE registeredHeight = VALUES(registeredHeight),"
                    ." lastPaidHeight = VALUES(lastPaidHeight), PoSePenalty = VALUES(PoSePenalty),"
                    ." PoSeRevivedHeight = VALUES(PoSeRevivedHeight), PoSeBanHeight = VALUES(PoSeBanHeight),"
                    ." revocationReason = VALUES(revocationReason), keyIDOwner = VALUES(keyIDOwner),"
                    ." pubKeyOperator = VALUES(pubKeyOperator), keyIDVoting = VALUES(keyIDVoting),"
                    ." addrIP = VALUES(addrIP), addrPort = VALUES(addrPort), payoutAddress = VALUES(payoutAddress),"
                    ." operatorRewardAddress = VALUES(operatorRewardAddress), StateDate = VALUES(StateDate)";

                if ($result92 = $mysqli->query($sql)) {
                    $protxstateinfo = $mysqli->info;
                }
                else {
                    $protxstateinfo = $mysqli->error;
                }
                unset($protxstatesql);
            }
            else {
                $protxstateinfo = "Nothing to do";
            }

            $mninfosql2 = array();
          $mnqueryexc2 = array();
          $skipinfo = "";
          foreach($payload['mninfo2'] as $mninfo) {
              $mniplong = ip2long($mninfo['MasternodeIP']);
              if ($mniplong === false) {
                  $mniplong = 0;
              }
              if (filter_var($mninfo['MasternodeIP'], FILTER_VALIDATE_IP) === false) {
                  $mnipv6 = "::";
                  if ((strlen($mninfo['MasternodeIP']) == 22) && (substr($mninfo['MasternodeIP'], -6) == ".onion")) {
                      $mntor = substr($mninfo['MasternodeIP'], 0, 16);
                  } else {
                      $skipinfo .= "\nError with " . $mninfo['MasternodeOutputHash'] . "-" . $mninfo['MasternodeOutputIndex'] . " IP = " . $mninfo['MasternodeIP'];
                      $mntor = false;
                  }
              } else {
                  $mnipv6 = $mninfo['MasternodeIP'];
                  $mntor = "";
              }
              if ($mntor !== false) {
                  $mnoutputhash = $mysqli->real_escape_string($mninfo['MasternodeOutputHash']);
                  $mninfosql2[] = sprintf("('%s', %d, %d, %d, '%s', %d, INET6_ATON('%s'), '%s', %d, %d, %d, %d, %d, '%s', '%s', '%s')",
                      $mnoutputhash,
                      $mninfo['MasternodeOutputIndex'],
                      $mninfo['MasternodeTestNet'],
                      $mninfo['MasternodeProtocol'],
                      $mysqli->real_escape_string($mninfo['MasternodePubkey']),
                      $mniplong,
                      $mnipv6,
                      $mysqli->real_escape_string($mntor),
                      $mninfo['MasternodePort'],
                      $mninfo['MasternodeLastSeen'],
                      $mninfo['MasternodeActiveSeconds'],
                      $mninfo['MasternodeLastPaid'],
                      $mninfo['MasternodeLastPaidBlock'],
                      $mysqli->real_escape_string($mninfo['MasternodeDaemonVersion']),
                      $mysqli->real_escape_string($mninfo['MasternodeSentinelVersion']),
                      $mysqli->real_escape_string($mninfo['MasternodeSentinelState'])
                  );
                  $mngeoip = geoip_record_by_name($mninfo['MasternodeIP']);
                  if ($mngeoip !== FALSE) {
                      $mnipcountry = $mngeoip["country_name"];
                      $mnipcountrycode = strtolower($mngeoip["country_code"]);
                  } else {
                      $mnipcountry = "Unknown";
                      $mnipcountrycode = "__";
                  }
                  $sqlpc[] = sprintf("(INET6_ATON('%s'), %d, %d, 'unknown', '%s', '%s')",
                      $mysqli->real_escape_string($mninfo['MasternodeIP']),
                      $mninfo['MasternodePort'],
                      $mninfo['MasternodeTestNet'],
                      $mnipcountry,
                      $mnipcountrycode
                  );
              }
          }

          $mninfo2info = false;
          if (count($mninfosql2) > 0) {
            $sql = "INSERT INTO cmd_info_masternode2 (MasternodeOutputHash, MasternodeOutputIndex, MasternodeTestNet,"
                  ." MasternodeProtocol, MasternodePubkey, MasternodeIP, MasternodeIPv6, MasternodeTor, MasternodePort,"
                  ." MasternodeLastSeen, MasternodeActiveSeconds, MasternodeLastPaid, MasternodeLastPaidBlock, MasternodeDaemonVersion,"
                  ." MasternodeSentinelVersion, MasternodeSentinelState) VALUE ".implode(',',$mninfosql2)
                  ." ON DUPLICATE KEY UPDATE MasternodeActiveSeconds = VALUES(MasternodeActiveSeconds),"
                  ." MasternodeLastSeen = VALUES(MasternodeLastSeen), MasternodeProtocol = VALUES(MasternodeProtocol),"
                  ." MasternodePubkey = VALUES(MasternodePubkey), MasternodeIP = VALUES(MasternodeIP), MasternodeIPv6 = VALUES(MasternodeIPv6),"
                  ." MasternodeTor = VALUES(MasternodeTor), MasternodePort = VALUES(MasternodePort), MasternodeLastPaid = VALUES(MasternodeLastPaid),"
                  ." MasternodeLastPaidBlock = VALUES(MasternodeLastPaidBlock), MasternodeDaemonVersion = VALUES(MasternodeDaemonVersion),"
                  ." MasternodeSentinelVersion = VALUES(MasternodeSentinelVersion), MasternodeSentinelState = VALUES(MasternodeSentinelState)";

            if ($result22 = $mysqli->query($sql)) {
                $mninfo2info = $mysqli->info . $skipinfo;
            }
            else {
                $mninfo2info = $mysqli->error;
            }
            unset($mninfosql2);
          }
          else {
            $mninfo2info = "Nothing to do";
          }

          $mnvotessql = array();
          foreach($payload['mnvotes'] as $mnvotes) {
            if (!array_key_exists($mnvotes['FromNodeUName'],$nodes)) {
              $response->setStatusCode(503, "Service Unavailable");
              $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
              return $response;
            }
            $mniplong = ip2long($mnvotes['MasternodeIP']);
            $nodeid = $nodes[$mnvotes['FromNodeUName']]['NodeId'];
            if ($mniplong !== false) {
              $mnvotessql[] = sprintf("(%d, %d, %d, %d, '%s')",
                                     $mniplong,
                                     $mnvotes['MasternodePort'],
                                     $mnvotes['MNTestNet'],
                                     $nodeid,
                                     $mnvotes['MasternodeVote']
                                    );
            }
          }
          $mnvotesinfo = false;
          if (count($mnvotessql) > 0) {
            $sql = "INSERT INTO cmd_info_masternode_votes (MasternodeIP, MasternodePort, MNTestNet, NodeID,"
                       ." MasternodeVote) VALUES ".implode(',',$mnvotessql)
                ." ON DUPLICATE KEY UPDATE MasternodeVote = VALUES(MasternodeVote)";

            if ($result9 = $mysqli->query($sql)) {
              $mnvotesinfo = $mysqli->info;
            }
            unset($mnvotessql);
          }

          $mnpksql = array();
          $mnpkexc = array();
          foreach($payload['mnpubkeys'] as $mninfo) {
            $mniplong = ip2long($mninfo['MasternodeIP']);
            if ($mniplong !== false) {
              $mnpksql[] = sprintf("(%d, %d, %d, '%s', 1)",
                                     $mniplong,
                                     $mninfo['MasternodePort'],
                                     $mninfo['MNTestNet'],
                                     $mysqli->real_escape_string($mninfo['MNPubKey'])
                                    );
              $mnpkexc[] = sprintf("!(MasternodeIP = %d AND MasternodePort = %d AND MNTestNet = %d AND MNPubKey = '%s')",$mniplong,$mninfo['MasternodePort'],$mninfo['MNTestNet'],$mysqli->real_escape_string($mninfo['MNPubKey']));
            }
          }

          $sql = sprintf("SELECT MasternodeIP, MasternodePort, MNTestNet, MNPubKey FROM cmd_info_masternode_pubkeys WHERE ".implode(' AND ',$mnpkexc)." AND MNLastReported != 0 AND MNTestNet = %d",$istestnet);
          $unlistedpk = array();
          if ($result1c = $mysqli->query($sql)) {
            while($row = $result1c->fetch_assoc()){
              $mnpksql[] = sprintf("(%d, %d, %d, '%s', 0)",
                                     $row['MasternodeIP'],
                                     $row['MasternodePort'],
                                     $row['MNTestNet'],
                                     $row['MNPubKey']
                                    );
            }
          }

          $mnpubkeysinfo = false;
          if (count($mnpksql) > 0) {
            $sql = "INSERT INTO cmd_info_masternode_pubkeys (MasternodeIP, MasternodePort, MNTestNet,"
                           ." MNPubKey, MNLastReported) VALUES ".implode(',',$mnpksql)
                ." ON DUPLICATE KEY UPDATE MNLastReported = VALUES(MNLastReported)";

            $result2b = $mysqli->query($sql);
            $mnpubkeysinfo = $mysqli->info;
            unset($mnpksql);
          }

          $mndonationsql = array();
          $mndonationexc = array();
          foreach($payload['mndonation'] as $mninfo) {
            $mniplong = ip2long($mninfo['MasternodeIP']);
            if ($mniplong !== false) {
              $mndonationsql[] = sprintf("(%d, %d, %d, '%s', %d, 1)",
                                     $mniplong,
                                     $mninfo['MasternodePort'],
                                     $mninfo['MNTestNet'],
                                     $mysqli->real_escape_string($mninfo['MNPubKey']),
                                     $mninfo['MNDonationPercentage']
                                    );
              $mndonationexc[] = sprintf("!(MasternodeIP = %d AND MasternodePort = %d AND MNTestNet = %d AND MNPubKey = '%s')",$mniplong,$mninfo['MasternodePort'],$mninfo['MNTestNet'],$mysqli->real_escape_string($mninfo['MNPubKey']));
            }
          }

          $sql = "SELECT MasternodeIP, MasternodePort, MNTestNet, MNPubKey FROM cmd_info_masternode_donation WHERE ".implode(' AND ',$mndonationexc).sprintf(" AND MNLastReported != 0 AND MNTestNet = %d",$istestnet);
          $unlisteddonation = array();
          if ($result1d = $mysqli->query($sql)) {
            while($row = $result1d->fetch_assoc()){
              $mndonationsql[] = sprintf("(%d, %d, %d, '%s', 0, 0)",
                                     $row['MasternodeIP'],
                                     $row['MasternodePort'],
                                     $row['MNTestNet'],
                                     $row['MNPubKey']
                                    );
            }
          }

          $mndonationinfo = false;
          if (count($mndonationsql) > 0) {
            $sql = "INSERT INTO cmd_info_masternode_donation (MasternodeIP, MasternodePort, MNTestNet,"
                           ." MNPubKey, MNDonationPercentage, MNLastReported) VALUES ".implode(',',$mndonationsql)
                ." ON DUPLICATE KEY UPDATE MNDonationPercentage = VALUES(MNDonationPercentage), MNLastReported = VALUES(MNLastReported)";

            $result2d = $mysqli->query($sql);
            $mndonationinfo = $mysqli->info;
            unset($mndonationsql);
          }

          $curnodes = array(array(),array());
          foreach($nodes as $node) {
            $curnodes[intval($node['NodeTestNet'])][] = $node['NodeId'];
          }
          $sql = sprintf("SELECT MasternodeIP, MasternodePort, MNTestNet FROM cmd_info_masternode WHERE MNTestNet = %d",$istestnet);
          $unlistedmn = array();
          if ($result1b = $mysqli->query($sql)) {
            while($row = $result1b->fetch_assoc()){
              $unlistedmn[] = $row;
            }
          }

          $mnlistsql = array();
          $inlist = array();
          foreach($payload['mnlist'] as $mninfo) {
            if (!array_key_exists($mninfo['FromNodeUName'],$nodes)) {
              $response->setStatusCode(503, "Service Unavailable");
              $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
              return $response;
            }
            $mniplong = ip2long($mninfo['MasternodeIP']);
            $nodeid = $nodes[$mninfo['FromNodeUName']]['NodeId'];
            if ($mniplong !== false) {
              $mnlistsql[] = sprintf("(%d, %d, %d, %d, '%s', %d, '%s')",
                                     $mniplong,
                                     $mninfo['MasternodePort'],
                                     $mninfo['MNTestNet'],
                                     $nodeid,
                                     $mninfo['MasternodeStatus'],
                                     $mninfo['MasternodeStatusPoS'],
                                     $mninfo['MasternodeStatusEx']
                                    );
              if (!array_key_exists($nodeid,$inlist)) {
                $inlist[$nodeid] = array();
              }
              $inlist[$nodeid][] = $mniplong.':'.$mninfo['MasternodePort'].':'.$mninfo['MNTestNet'];
            }
          }
          foreach($unlistedmn as $mninfo) {
            foreach($curnodes[$mninfo['MNTestNet']] as $nodeid) {
              if (array_key_exists($nodeid,$inlist) && (!in_array($mninfo['MasternodeIP'].':'.$mninfo['MasternodePort'].':'.$mninfo['MNTestNet'],$inlist[$nodeid]))) {
                $mnlistsql[] = sprintf("(%d, %d, %d, %d, 'unlisted',-1,'')",
                                       $mninfo['MasternodeIP'],
                                       $mninfo['MasternodePort'],
                                       $mninfo['MNTestNet'],
                                       $nodeid
                                  );
              }
            }
          }

          $mnlistinfo = false;
          if (count($mnlistsql) > 0) {
            $sql = "INSERT INTO cmd_info_masternode_list (MasternodeIP, MasternodePort, MNTestNet, NodeID,"
                       ." MasternodeStatus, MasternodeStatusPoS, MasternodeStatusEx) VALUES ".implode(',',$mnlistsql)
                ." ON DUPLICATE KEY UPDATE MasternodeStatus = VALUES(MasternodeStatus), MasternodeStatusPoS = VALUES(MasternodeStatusPoS), MasternodeStatusEx = VALUES(MasternodeStatusEx)";

            if ($result3 = $mysqli->query($sql)) {
              $mnlistinfo = $mysqli->info;
            }
            unset($mnlistsql);
          }

          $sql = sprintf("SELECT MasternodeOutputHash, MasternodeOutputIndex, MasternodeTestNet FROM cmd_info_masternode2 WHERE MasternodeTestNet = %d",$istestnet);
          $unlistedmn2 = array();
          if ($result1xb = $mysqli->query($sql)) {
            while($row = $result1xb->fetch_assoc()){
              $unlistedmn2[] = $row;
            }
          }

          // v12 handling (masternodes ID = vins)
          $mnlist2sql = array();
          $inlist2 = array();
          foreach($payload['mnlist2'] as $mninfo) {
            if (!array_key_exists($mninfo['FromNodeUName'],$nodes)) {
              $response->setStatusCode(503, "Service Unavailable");
              $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
              return $response;
            }
            $nodeid = $nodes[$mninfo['FromNodeUName']]['NodeId'];
            $mnlist2sql[] = sprintf("('%s', %d, %d, %d, '%s', '%s')",
                                     $mninfo['MasternodeOutputHash'],
                                     $mninfo['MasternodeOutputIndex'],
                                     $mninfo['MasternodeTestNet'],
                                     $nodeid,
                                     $mninfo['MasternodeStatus'],
                                     $mninfo['MasternodeStatusEx']
                                    );
            if (!array_key_exists($nodeid,$inlist2)) {
              $inlist2[$nodeid] = array();
            }
            $inlist2[$nodeid][] = $mninfo['MasternodeOutputHash']."-".$mninfo['MasternodeOutputIndex']."-".$mninfo['MasternodeTestNet'];
          }
          foreach($unlistedmn2 as $mninfo) {
            foreach($curnodes[$mninfo['MasternodeTestNet']] as $nodeid) {
              if (array_key_exists($nodeid,$inlist2) && (!in_array($mninfo['MasternodeOutputHash']."-".$mninfo['MasternodeOutputIndex']."-".$mninfo['MasternodeTestNet'],$inlist2[$nodeid]))) {
                $mnlist2sql[] = sprintf("('%s', %d, %d, %d, 'unlisted', '')",
                                     $mninfo['MasternodeOutputHash'],
                                     $mninfo['MasternodeOutputIndex'],
                                     $mninfo['MasternodeTestNet'],
                                     $nodeid
                                  );
              }
            }
          }

          $mnlist2info = false;
          if (count($mnlist2sql) > 0) {
            $sql = "INSERT INTO cmd_info_masternode2_list (MasternodeOutputHash, MasternodeOutputIndex, MasternodeTestNet, NodeID,"
                       ." MasternodeStatus, MasternodeStatusEx) VALUES ".implode(',',$mnlist2sql)
                ." ON DUPLICATE KEY UPDATE MasternodeStatus = VALUES(MasternodeStatus), MasternodeStatusEx = VALUES(MasternodeStatusEx)";

            if ($result3x = $mysqli->query($sql)) {
              $mnlist2info = $mysqli->info;
            }
            else {
              $mnlist2info = $mysqli->errno.": ".$mysqli->error;
            }
            unset($mnlist2sql);
          }
          else {
            $mnlist2info = "Nothing to do";
          }

          $pcinfo = false;
          if (count($sqlpc) > 0) {
            $sql = "INSERT IGNORE INTO cmd_portcheck (NodeIP, NodePort, NodeTestNet, NodePortCheck, NodeCountry, NodeCountryCode)"
                  ." VALUES ".implode(',',$sqlpc);
            if ($result4 = $mysqli->query($sql)) {
              $pcinfo = $mysqli->info;
            }
          }

          $activemncount = array(0,0);
          $networkhashps = 0;
          $governancenextsuperblock = 0;
          $governancebudget = 0;
          $pricebtc = 0.0;
          $priceeuro = 0.0;
          $priceusd = 0.0;
          foreach($payload['stats'] as $statid => $statval) {
            if ($statid == "networkhashps") {
              $networkhashps = intval($statval);
            }
            elseif ($statid == "governancenextsuperblock") {
              $governancenextsuperblock = intval($statval);
            }
            elseif ($statid == "governancebudget") {
              $governancebudget = floatval($statval);
            }
          }

          $sqlstats2 = array();
          $activemncount = 0;
          $uniquemnips = 0;
          dmn_masternodes_count($mysqli,$istestnet,$activemncount,$uniquemnips);
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",'mnactive',$activemncount,time());
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",'mnuniqiptest',$uniquemnips,time());

          $teststr = "";
          if ($istestnet == 1) {
              $teststr = "test";
          }
          $sql = "SELECT StatKey, StatValue FROM cmd_stats_values WHERE StatKey = 'usdbtc' OR StatKey = 'btcdrk' OR StatKey = 'eurobtc' OR StatKey = 'mnactiveath$teststr'";
          $tmp = array("btcdrk" => 0.0, "eurobtc" => 0.0, "usdbtc" => 0.0, "mnactiveath$teststr" => 0);
          if ($result = $mysqli->query($sql)) {
            while ($row = $result->fetch_assoc()) {
              $tmp[$row['StatKey']] = floatval($row['StatValue']);
            }
            $result->free();
          }
          $pricebtc = $tmp['btcdrk'];
          $priceeur = $pricebtc*$tmp['eurobtc'];
          $priceusd = $pricebtc*$tmp['usdbtc'];
          $activemncountath = $tmp["mnactiveath$teststr"];
          if ($activemncount > $activemncountath) {
            $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')","mnactiveath$teststr",$activemncount,time());
          }

          $sqlstats[] = sprintf("(%d,NOW(),%d,%d,%01.9f,%01.9f,%01.9f)",
                                       $istestnet,
                                       $activemncount,
                                       $networkhashps,
                                       $pricebtc,
                                       $priceusd,
                                       $priceeur
                                  );
          $statkey = "networkhashpers";
          if ($istestnet == 1) {
            $statkey .= "test";
          }
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$networkhashps,time());
          if ((isset($governancenextsuperblock)) && (!is_null($governancenextsuperblock)) && ($governancenextsuperblock > 0)) {
            $statkey = "governancesb";
            if ($istestnet == 1) {
              $statkey .= "test";
            }
            $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$governancenextsuperblock,time());
          }
          if ((isset($governancebudget)) && (!is_null($governancebudget)) && ($governancebudget > 0)) {
            $statkey = "governancebudget";
            if ($istestnet == 1) {
              $statkey .= "test";
            }
            $sqlstats2[] = sprintf("('%s','%s',%01.9f,'dashninja')", $statkey, $governancebudget, time());
          }

          $statsinfo = false;
          if (count($sqlstats) > 0) {
            $sql = "INSERT IGNORE INTO cmd_stats_history (TestNet, StatDate, ActiveMNCount, NetworkHashPerSec, PriceBTC, PriceUSD, PriceEUR)"
                  ." VALUES ".implode(',',$sqlstats);
            if ($result5 = $mysqli->query($sql)) {
              $statsinfo = $mysqli->info;
              if (is_null($statsinfo)) {
                $statsinfo = true;
              }
            }
          }

          if (count($sqlstats2) > 0) {
            $sql = "INSERT INTO cmd_stats_values (StatKey, StatValue, LastUpdate, Source)"
              ." VALUES ".implode(',',$sqlstats2)
              ." ON DUPLICATE KEY UPDATE StatValue = VALUES(StatValue), LastUpdate = VALUES(LastUpdate), Source = VALUES(Source)";

            if ($result = $mysqli->query($sql)) {
              $stats2info = $mysqli->info;
              if (is_null($stats2info)) {
                $stats2info = true;
              }
            }
          }

          $sqlbudgetshow = array();
          foreach($payload['mnbudgetshow'] as $mnbudget) {
            $sqlbudgetshow[] = sprintf("(%d, '%s','%s','%s','%s',%d,%d,%d,%d,'%s',%.8f,%d,%d,%d,%.8f,%.8f,%d,%d,'%s',%d,NOW(),NOW())",
                                          $mnbudget["BudgetTesnet"],
                                          $mysqli->real_escape_string($mnbudget["Hash"]),
                                          $mysqli->real_escape_string($mnbudget["BudgetId"]),
                                          $mysqli->real_escape_string($mnbudget["URL"]),
                                          $mysqli->real_escape_string($mnbudget["FeeHash"]),
                                          $mnbudget["BlockStart"],
                                          $mnbudget["BlockEnd"],
                                          $mnbudget["TotalPaymentCount"],
                                          $mnbudget["RemainingPaymentCount"],
                                          $mysqli->real_escape_string($mnbudget["PaymentAddress"]),
                                          $mnbudget["Ratio"],
                                          $mnbudget["Yeas"],
                                          $mnbudget["Nays"],
                                          $mnbudget["Abstains"],
                                          $mnbudget["TotalPayment"],
                                          $mnbudget["MonthlyPayment"],
                                          $mnbudget["IsEstablished"] ? 1 : 0,
                                          $mnbudget["IsValid"] ? 1 : 0,
                                          $mysqli->real_escape_string($mnbudget["IsValidReason"]),
                                          $mnbudget["fValid"] ? 1 : 0
                                        );
          }
          $mnbudgetshowinfo = false;
          if (count($sqlbudgetshow) > 0) {
            $sql = "INSERT INTO `cmd_budget` (BudgetTestnet, `BudgetHash`, `BudgetId`, `BudgetURL`, `FeeHash`, `BlockStart`, `BlockEnd`,"
                  ." `TotalPaymentCount`, `RemainingPaymentCount`, `PaymentAddress`, `Ratio`, `Yeas`, `Nays`, `Abstains`,"
                  ." `TotalPayment`, `MonthlyPayment`, `IsEstablished`, `IsValid`, `IsValidReason`, `fValid`, `FirstReported`, LastReported)"
                  ." VALUES ".implode(',',$sqlbudgetshow)
                  ." ON DUPLICATE KEY UPDATE BudgetId = VALUES(BudgetId), BudgetURL = VALUES(BudgetURL), FeeHash = VALUES(FeeHash),"
                  ." BlockStart = VALUES(BlockStart), BlockEnd = VALUES(BlockEnd), TotalPaymentCount = VALUES(TotalPaymentCount),"
                  ." RemainingPaymentCount = VALUES(RemainingPaymentCount), PaymentAddress = VALUES(PaymentAddress),"
                  ." Ratio = VALUES(Ratio), Yeas = VALUES(Yeas), Nays = VALUES(Nays), Abstains = VALUES(Abstains),"
                  ." TotalPayment = VALUES(TotalPayment), MonthlyPayment = VALUES(MonthlyPayment), IsEstablished = VALUES(IsEstablished),"
                  ." IsValid = VALUES(IsValid), IsValidReason = VALUES(IsValidReason), fValid = VALUES(fValid), LastReported = VALUES(LastReported)";
            if ($result60 = $mysqli->query($sql)) {
              $mnbudgetshowinfo = $mysqli->info;
              if (is_null($mnbudgetshowinfo)) {
                $mnbudgetshowinfo = true;
              }
            }
          }

          $sqlbudgetprojection = array();
          foreach($payload['mnbudgetprojection'] as $mnbudget) {
            $sqlbudgetprojection[] = sprintf("(%d, '%s','%s','%s',%d,%d,%d,%d,'%s',%.8f,%d,%d,%d,%.8f,%.8f,%.8f,%.8f,%d,'%s',%d,NOW(),NOW())",
                                          $mnbudget["BudgetTesnet"],
                                          $mysqli->real_escape_string($mnbudget["Hash"]),
                                          $mysqli->real_escape_string($mnbudget["BudgetId"]),
                                          $mysqli->real_escape_string($mnbudget["URL"]),
                                          $mnbudget["BlockStart"],
                                          $mnbudget["BlockEnd"],
                                          $mnbudget["TotalPaymentCount"],
                                          $mnbudget["RemainingPaymentCount"],
                                          $mysqli->real_escape_string($mnbudget["PaymentAddress"]),
                                          $mnbudget["Ratio"],
                                          $mnbudget["Yeas"],
                                          $mnbudget["Nays"],
                                          $mnbudget["Abstains"],
                                          $mnbudget["TotalPayment"],
                                          $mnbudget["MonthlyPayment"],
                                          $mnbudget["Alloted"],
                                          $mnbudget["TotalBudgetAlloted"],
                                          $mnbudget["IsValid"] ? 1 : 0,
                                          $mysqli->real_escape_string($mnbudget["IsValidReason"]),
                                          $mnbudget["fValid"] ? 1 : 0
                                        );
          }
          $mnbudgetprojectioninfo = false;
          if (count($sqlbudgetprojection) > 0) {
            $sql = "INSERT INTO `cmd_budget_projection` (BudgetTestnet, `BudgetHash`, `BudgetId`, `BudgetURL`, `BlockStart`, `BlockEnd`,"
                  ." `TotalPaymentCount`, `RemainingPaymentCount`, `PaymentAddress`, `Ratio`, `Yeas`, `Nays`, `Abstains`,"
                  ." `TotalPayment`, `MonthlyPayment`, Alloted, TotalBudgetAlloted, `IsValid`, `IsValidReason`, `fValid`, `FirstReported`, LastReported)"
                  ." VALUES ".implode(',',$sqlbudgetprojection)
                  ." ON DUPLICATE KEY UPDATE BudgetId = VALUES(BudgetId), BudgetURL = VALUES(BudgetURL),"
                  ." BlockStart = VALUES(BlockStart), BlockEnd = VALUES(BlockEnd), TotalPaymentCount = VALUES(TotalPaymentCount),"
                  ." RemainingPaymentCount = VALUES(RemainingPaymentCount), PaymentAddress = VALUES(PaymentAddress),"
                  ." Ratio = VALUES(Ratio), Yeas = VALUES(Yeas), Nays = VALUES(Nays), Abstains = VALUES(Abstains),"
                  ." TotalPayment = VALUES(TotalPayment), MonthlyPayment = VALUES(MonthlyPayment), Alloted = VALUES(Alloted),"
                  ." TotalBudgetAlloted = VALUES(TotalBudgetAlloted), IsValid = VALUES(IsValid), IsValidReason = VALUES(IsValidReason),"
                  ." fValid = VALUES(fValid), LastReported = VALUES(LastReported)";
            if ($result61 = $mysqli->query($sql)) {
              $mnbudgetprojectioninfo = $mysqli->info;
              if (is_null($mnbudgetprojectioninfo)) {
                $mnbudgetprojectioninfo = true;
              }
            }
          }

            $sqlbudgetfinal = array();
            foreach($payload['mnbudgetfinal'] as $mnbudget) {
                $sqlbudgetfinal[] = sprintf("(%d, '%s','%s','%s',%d,%d,%d,'%s',%d,'%s','%s',NOW(),NOW())",
                    $mnbudget["BudgetTesnet"],
                    $mysqli->real_escape_string($mnbudget["Hash"]),
                    $mysqli->real_escape_string($mnbudget["FeeTX"]),
                    $mysqli->real_escape_string($mnbudget["BudgetName"]),
                    $mnbudget["BlockStart"],
                    $mnbudget["BlockEnd"],
                    $mnbudget["VoteCount"],
                    $mysqli->real_escape_string($mnbudget["Status"]),
                    $mnbudget["IsValid"] ? 1 : 0,
                    $mysqli->real_escape_string($mnbudget["IsValidReason"]),
                    $mysqli->real_escape_string($mnbudget["Proposals"])
                );
            }
            $mnbudgetfinalinfo = false;
            if (count($sqlbudgetfinal) > 0) {
                $sql = "INSERT INTO `cmd_budget_final` (BudgetTestnet, `BudgetHash`, `FeeTx`, `BudgetName`, `BlockStart`, `BlockEnd`,"
                    ." `VoteCount`, `Status`, `IsValid`, `IsValidReason`, `Proposals`, `FirstReported`, LastReported)"
                    ." VALUES ".implode(',',$sqlbudgetfinal)
                    ." ON DUPLICATE KEY UPDATE BudgetName = VALUES(BudgetName), FeeTx = VALUES(FeeTx),"
                    ." BlockStart = VALUES(BlockStart), BlockEnd = VALUES(BlockEnd), VoteCount = VALUES(VoteCount),"
                    ." Status = VALUES(Status), IsValid = VALUES(IsValid), IsValidReason = VALUES(IsValidReason),"
                    ." Proposals = VALUES(Proposals), LastReported = VALUES(LastReported)";
                if ($result62 = $mysqli->query($sql)) {
                    $mnbudgetfinalinfo = $mysqli->info;
                    if (is_null($mnbudgetfinalinfo)) {
                        $mnbudgetfinalinfo = true;
                    }
                }
            }

            $sqlbudgetvotes = array();
            foreach($payload['mnbudgetvotes'] as $mnbudget) {
                $sqlbudgetvotes[] = sprintf("(%d, '%s','%s',%d,'%s','%s',%d,%d)",
                    $mnbudget["BudgetTestnet"],
                    $mysqli->real_escape_string($mnbudget["BudgetId"]),
                    $mysqli->real_escape_string($mnbudget["MasternodeOutputHash"]),
                    $mnbudget["MasternodeOutputIndex"],
                    $mysqli->real_escape_string($mnbudget["VoteHash"]),
                    $mysqli->real_escape_string($mnbudget["VoteValue"]),
                    $mnbudget["VoteTime"],
                    $mnbudget["VoteIsValid"] ? 1 : 0
                );
            }
            $mnbudgetvotesinfo = false;
            if (count($sqlbudgetvotes) > 0) {
                $sql = "INSERT INTO `cmd_budget_votes` (BudgetTestnet, BudgetId, MasternodeOutputHash,"
                    ." MasternodeOutputIndex, VoteHash, VoteValue, VoteTime, VoteIsValid)"
                    ." VALUES ".implode(',',$sqlbudgetvotes)
                    ." ON DUPLICATE KEY UPDATE VoteHash = VALUES(VoteHash), VoteValue = VALUES(VoteValue), "
                    ." VoteTime = VALUES(VoteTime), VoteIsValid = VALUES(VoteIsValid)";
                if ($result605 = $mysqli->query($sql)) {
                    $mnbudgetvotesinfo = $mysqli->info;
                    if (is_null($mnbudgetvotesinfo)) {
                        $mnbudgetvotesinfo = true;
                    }
                }
                else {
                    $mnbudgetvotesinfo = $mysqli->error;
                }
            }

            // gobjects proposals 12.1+
            $sqlgobjectproposals = array();
            foreach($payload['gobjproposals'] as $proposal) {
                $sqlgobjectproposals[] = sprintf("(%d, '%s','%s','%s',%F,%d,%d,'%s','%s',%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s',NOW(),NOW())",
                    $proposal["Testnet"],
                    $mysqli->real_escape_string($proposal["hash"]),
                    $mysqli->real_escape_string($proposal["name"]),
                    substr(trim($mysqli->real_escape_string($proposal["payment_address"])),0,34),
                    floatval($proposal["payment_amount"]),
                    intval($proposal["start_epoch"]),
                    intval($proposal["end_epoch"]),
                    $mysqli->real_escape_string($proposal["url"]),
                    $mysqli->real_escape_string($proposal["gobject"]["CollateralHash"]),
                    intval($proposal["gobject"]["AbsoluteYesCount"]),
                    intval($proposal["gobject"]["YesCount"]),
                    intval($proposal["gobject"]["NoCount"]),
                    intval($proposal["gobject"]["AbstainCount"]),
                    $proposal["gobject"]["fBlockchainValidity"] ? 1 : 0,
                    $proposal["gobject"]["fCachedValid"] ? 1 : 0,
                    $proposal["gobject"]["fCachedFunding"] ? 1 : 0,
                    $proposal["gobject"]["fCachedDelete"] ? 1 : 0,
                    $proposal["gobject"]["fCachedEndorsed"] ? 1 : 0,
                    $mysqli->real_escape_string($proposal["gobject"]["IsValidReason"])
                );
            }
            $gobjectproposalsinfo = false;
            if (count($sqlgobjectproposals) > 0) {
                $sql = "INSERT INTO `cmd_gobject_proposals` (GovernanceObjectTestnet, GovernanceObjectId, GovernanceObjectName, GovernanceObjectPaymentAddress,"
                    ." GovernanceObjectPaymentAmount, GovernanceObjectEpochStart, GovernanceObjectEpochEnd, GovernanceObjectURL, GovernanceObjectCollateral,"
                    ." GovernanceObjectVotesAbsoluteYes, GovernanceObjectVotesYes, GovernanceObjectVotesNo, GovernanceObjectVotesAbstain, GovernanceObjectBlockchainValidity,"
                    ." GovernanceObjectCachedValid, GovernanceObjectCachedFunding, GovernanceObjectCachedDelete, GovernanceObjectCachedEndorsed, GovernanceObjectIsValidReason, FirstReported, LastReported)"
                    ." VALUES ".implode(',',$sqlgobjectproposals)
                    ." ON DUPLICATE KEY UPDATE GovernanceObjectName = VALUES(GovernanceObjectName), GovernanceObjectPaymentAddress = VALUES(GovernanceObjectPaymentAddress),"
                    ." GovernanceObjectPaymentAmount = VALUES(GovernanceObjectPaymentAmount), GovernanceObjectEpochStart = VALUES(GovernanceObjectEpochStart),"
                    ." GovernanceObjectEpochEnd = VALUES(GovernanceObjectEpochEnd), GovernanceObjectURL = VALUES(GovernanceObjectURL),"
                    ." GovernanceObjectCollateral = VALUES(GovernanceObjectCollateral), GovernanceObjectVotesAbsoluteYes = VALUES(GovernanceObjectVotesAbsoluteYes),"
                    ." GovernanceObjectVotesYes = VALUES(GovernanceObjectVotesYes), GovernanceObjectVotesNo = VALUES(GovernanceObjectVotesNo),"
                    ." GovernanceObjectVotesAbstain = VALUES(GovernanceObjectVotesAbstain), GovernanceObjectBlockchainValidity = VALUES(GovernanceObjectBlockchainValidity),"
                    ." GovernanceObjectCachedValid = VALUES(GovernanceObjectCachedValid), GovernanceObjectCachedFunding = VALUES(GovernanceObjectCachedFunding),"
                    ." GovernanceObjectCachedDelete = VALUES(GovernanceObjectCachedDelete), GovernanceObjectCachedEndorsed = VALUES(GovernanceObjectCachedEndorsed),"
                    ." GovernanceObjectIsValidReason = VALUES(GovernanceObjectIsValidReason), LastReported = VALUES(LastReported)";
                if ($result70 = $mysqli->query($sql)) {
                    $gobjectproposalsinfo = $mysqli->info;
                    if (is_null($gobjectproposalsinfo)) {
                        $gobjectproposalsinfo = true;
                    }
                }
                else {
                    $gobjectproposalsinfo = $mysqli->errno.": ".$mysqli->error;
                }
            }

            // gobjects triggers 12.1+
            $sqlgobjecttriggers = array();
            $sqlgobjecttriggerspayments = array();
            $sqlgobjecttriggerspaymentstrim = array();
            foreach($payload['gobjtriggers'] as $triggers) {
                $objhash = $mysqli->real_escape_string($triggers["hash"]);
                $sqlgobjecttriggers[] = sprintf("(%d,'%s',%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s',NOW(),NOW())",
                    $triggers["Testnet"],
                    $objhash,
                    intval($triggers["event_block_height"]),
                    intval($triggers["gobject"]["AbsoluteYesCount"]),
                    intval($triggers["gobject"]["YesCount"]),
                    intval($triggers["gobject"]["NoCount"]),
                    intval($triggers["gobject"]["AbstainCount"]),
                    $triggers["gobject"]["fBlockchainValidity"] ? 1 : 0,
                    $triggers["gobject"]["fCachedValid"] ? 1 : 0,
                    $triggers["gobject"]["fCachedFunding"] ? 1 : 0,
                    $triggers["gobject"]["fCachedDelete"] ? 1 : 0,
                    $triggers["gobject"]["fCachedEndorsed"] ? 1 : 0,
                    $mysqli->real_escape_string($triggers["gobject"]["IsValidReason"])
                );
                $addr = explode("|",$triggers["payment_addresses"]);
                $amnt = explode("|",$triggers["payment_amounts"]);
                if (array_key_exists("proposal_hashes",$triggers)) {
                  $hash = explode("|",$triggers["proposal_hashes"]);
                }
                // Temporary hack while sentinel is updated with proposals hashes
                else {
                  $hash = array();
                  foreach($addr as $x) {
                    $hash[] = "";
                  }
                }
                if ((count($addr) == count($amnt)) && (count($addr) == count($hash))) {
                  foreach($addr as $x => $address) {
                      $sqlgobjecttriggerspayments[] = sprintf("(%d,'%s',%d,'%s',%F,'%s')",
                          $triggers["Testnet"],
                          $objhash,
                          $x,
                          $address,
                          floatval($amnt[$x]),
                          $mysqli->real_escape_string($hash[$x])
                      );
                  }
                  $sqlgobjecttriggerspaymentstrim[] = sprintf("DELETE FROM cmd_gobject_triggers_payments WHERE GovernanceObjectTestnet = %d AND GovernanceObjectId = '%s' AND GovernanceObjectPaymentPosition >= %d",
                     $triggers["Testnet"],
                     $objhash,
                     count($addr)
                  );
                }
            }
            $gobjecttriggersinfo = false;
            $gobjecttriggersinfopayments = false;
            $gobjecttriggersinfopaymentstrim = array(false);
            if (count($sqlgobjecttriggers) > 0) {
                $sql = "INSERT INTO `cmd_gobject_triggers` (GovernanceObjectTestnet, GovernanceObjectId, GovernanceObjectEventBlockHeight,"
                    ." GovernanceObjectVotesAbsoluteYes, GovernanceObjectVotesYes, GovernanceObjectVotesNo, GovernanceObjectVotesAbstain, GovernanceObjectBlockchainValidity,"
                    ." GovernanceObjectCachedValid, GovernanceObjectCachedFunding, GovernanceObjectCachedDelete, GovernanceObjectCachedEndorsed, GovernanceObjectIsValidReason, FirstReported, LastReported)"
                    ." VALUES ".implode(',',$sqlgobjecttriggers)
                    ." ON DUPLICATE KEY UPDATE GovernanceObjectEventBlockHeight = VALUES(GovernanceObjectEventBlockHeight),"
                    ." GovernanceObjectVotesAbsoluteYes = VALUES(GovernanceObjectVotesAbsoluteYes),"
                    ." GovernanceObjectVotesYes = VALUES(GovernanceObjectVotesYes), GovernanceObjectVotesNo = VALUES(GovernanceObjectVotesNo),"
                    ." GovernanceObjectVotesAbstain = VALUES(GovernanceObjectVotesAbstain), GovernanceObjectBlockchainValidity = VALUES(GovernanceObjectBlockchainValidity),"
                    ." GovernanceObjectCachedValid = VALUES(GovernanceObjectCachedValid), GovernanceObjectCachedFunding = VALUES(GovernanceObjectCachedFunding),"
                    ." GovernanceObjectCachedDelete = VALUES(GovernanceObjectCachedDelete), GovernanceObjectCachedEndorsed = VALUES(GovernanceObjectCachedEndorsed),"
                    ." GovernanceObjectIsValidReason = VALUES(GovernanceObjectIsValidReason), LastReported = VALUES(LastReported)";
                if ($result702 = $mysqli->query($sql)) {
                    $gobjecttriggersinfo = $mysqli->info;
                    if (is_null($gobjecttriggersinfo)) {
                        $gobjecttriggersinfo = true;
                    }
                }
                else {
                    $gobjecttriggersinfo = $mysqli->errno.": ".$mysqli->error;
                }
                if (count($sqlgobjecttriggerspayments) > 0) {
                    $sql = "INSERT INTO `cmd_gobject_triggers_payments` (GovernanceObjectTestnet, GovernanceObjectId, GovernanceObjectPaymentPosition,"
                        ." GovernanceObjectPaymentAddress, GovernanceObjectPaymentAmount, GovernanceObjectPaymentProposalHash)"
                        ." VALUES ".implode(',',$sqlgobjecttriggerspayments)
                        ." ON DUPLICATE KEY UPDATE GovernanceObjectPaymentAddress = VALUES(GovernanceObjectPaymentAddress),"
                        ." GovernanceObjectPaymentAmount = VALUES(GovernanceObjectPaymentAmount),"
                        ." GovernanceObjectPaymentProposalHash = VALUES(GovernanceObjectPaymentProposalHash)";
                    if ($result703 = $mysqli->query($sql)) {
                        $gobjecttriggersinfopayments = $mysqli->info;
                        if (is_null($gobjecttriggersinfopayments)) {
                            $gobjecttriggersinfopayments = true;
                        }
                        $gobjecttriggersinfopaymentstrim = array();
                        foreach($sqlgobjecttriggerspaymentstrim as $sql) {
                            if ($result703a = $mysqli->query($sql)) {
                                $gobjecttriggersinfopaymentstrimtest = $mysqli->info;
                                if (is_null($gobjecttriggersinfopaymentstrimtest)) {
                                    $gobjecttriggersinfopaymentstrimtest = true;
                                }
                                $gobjecttriggersinfopaymentstrim[] = $gobjecttriggersinfopaymentstrimtest;
                            } else {
                                $gobjecttriggersinfopaymentstrim[] = $mysqli->errno . ": " . $mysqli->error;
                            }
                        }
                    }
                    else {
                        $gobjecttriggersinfopayments = $mysqli->errno.": ".$mysqli->error;
                    }
                }
            }

            // gobjects votes 12.1+
            $sqlobjectvotes = array();
            foreach($payload['gobjvotes'] as $objectvote) {
                $sqlobjectvotes[] = sprintf("(%d, '%s','%s',%d,'%s','%s',%d)",
                    $objectvote["GovernanceObjectTestnet"],
                    $mysqli->real_escape_string($objectvote["GovernanceObjectId"]),
                    $mysqli->real_escape_string($objectvote["MasternodeOutputHash"]),
                    $objectvote["MasternodeOutputIndex"],
                    $mysqli->real_escape_string($objectvote["VoteHash"]),
                    $mysqli->real_escape_string($objectvote["VoteValue"]),
                    $objectvote["VoteTime"]
                );
            }
            $objvotesinfo = false;
            if (count($sqlobjectvotes) > 0) {
                $sql = "INSERT INTO cmd_gobject_votes (GovernanceObjectTestnet, GovernanceObjectId, MasternodeOutputHash,"
                    ." MasternodeOutputIndex, VoteHash, VoteValue, VoteTime)"
                    ." VALUES ".implode(',',$sqlobjectvotes)
                    ." ON DUPLICATE KEY UPDATE VoteHash = VALUES(VoteHash), VoteValue = VALUES(VoteValue), "
                    ." VoteTime = VALUES(VoteTime)";
                if ($result705 = $mysqli->query($sql)) {
                    $objvotesinfo = $mysqli->info;
                    if (is_null($objvotesinfo)) {
                        $objvotesinfo = true;
                    }
                }
                else {
                    $objvotesinfo = $mysqli->error;
                }
            }


            //Change the HTTP status
          $response->setStatusCode(202, "Accepted");
          $response->setJsonContent(array('status' => 'OK', 'data' => array(
                                                                            'mnbudgetshow' => $mnbudgetshowinfo,
                                                                            'mnbudgetfinal' => $mnbudgetfinalinfo,
                                                                            'mnbudgetprojection' => $mnbudgetprojectioninfo,
                                                                            'mnbudgetvotes' => $mnbudgetvotesinfo,
                                                                            'gobjproposals' => $gobjectproposalsinfo,
                                                                            'gobjvotes' => $objvotesinfo,
                                                                            'gobjtriggers' => $gobjecttriggersinfo,
                                                                            'gobjtriggerspayments' => $gobjecttriggersinfopayments,
                                                                            'gobjtriggerspaymentstrim' => implode("|",$gobjecttriggersinfopaymentstrim),
                                                                            'mnlist' => $mnlistinfo,
                                                                            'mnlist2' => $mnlist2info,
                                                                            'mninfo' => $mninfoinfo,
                                                                            'mninfo2' => $mninfo2info,
                                                                            'mnpubkeys' => $mnpubkeysinfo,
                                                                            'mndonation' => $mndonationinfo,
                                                                            'mnvotes' => $mnvotesinfo,
                                                                            'nodes' => $nodesinfo,
                                                                            'portcheck' => $pcinfo,
                                                                            'protx' => $protxinfo,
                                                                            'protxstate' => $protxstateinfo,
                                                                            'spork' => $sporkinfo,
                                                                            'stats' => $statsinfo,
                                                                            'stats2' => $stats2info
                                                                           )));

        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR',
                                          'messages' => array("INSERT INTO cmd_nodes_status",$mysqli->errno.': '.$mysqli->error),
                                          'debug' => $sql));
        }
      }
      else {
        $response->setStatusCode(503, "Service Unavailable");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Hub should have $numnodes nodes (reports ".count($payload['nodes']).")")));
      }
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', array('messages' => $mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// POOLS
// ----------------------------------------------------------------------------
// End-point to retrieve all known pools pubkeys
// HTTP method:
//   GET
// Parameters:
//   None
// ============================================================================
$app->get('/pools', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    // Retrieve all known nodes for current hub
    $sql = "SELECT PoolPubKey, PoolDescription FROM cmd_pools_pubkey";
    $pubkeys = array();
    if ($result = $mysqli->query($sql)) {
      while($row = $result->fetch_array()){
        $pubkeys[$row[0]] = $row[1];
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('poolpubkeys' => $pubkeys)));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// PORTCHECK/CONFIG (for dmnportcheck)
// ----------------------------------------------------------------------------
// End-point to retrieve port check configuration
// HTTP method:
//   GET
// Parameters:
//   none
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of portcheck (only if status is OK)
// ============================================================================
$app->get('/portcheck/config', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => 'Payload (or CONTENT_LENGTH) is missing'));
  }
  else {
    $cachefnam = CACHEFOLDER."dashninja_cmd_portcheck_config";
    $cachevalid = (is_readable($cachefnam) && ((filemtime($cachefnam)+7200)>=time()));
    if ($cachevalid) {
      $config = unserialize(file_get_contents($cachefnam));
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => $config));
    }
    else {
      // Retrieve the configuration for the port checker
      $sql = "SELECT TestNet, Version, SatoshiVersion, ProtocolVersion, HEX(ProtocolMagic) ProtocolMagic FROM cmd_portcheck_config ORDER BY TestNet";
      $config = array();
      if ($result = $mysqli->query($sql)) {
        while($row = $result->fetch_assoc()){
          $config[intval($row['TestNet'])] = $row;
        }

        file_put_contents($cachefnam,serialize($config),LOCK_EX);
        //Change the HTTP status
        $response->setStatusCode(200, "OK");
        $response->setJsonContent(array('status' => 'OK', 'data' => $config));
      }
      else {
        $response->setStatusCode(503, "Service Unavailable");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => $mysqli->errno.': '.$mysqli->error));
      }
    }
  }
  return $response;

});

// ============================================================================
// PORTCHECK/LIST (for dmnportcheck)
// ----------------------------------------------------------------------------
// End-point to retrieve port check list of nodes
// HTTP method:
//   GET
// Parameters:
//   none
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of portcheck (only if status is OK)
// ============================================================================
$app->get('/portcheck/list', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $request = $app->request;

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {

    // Retrieve all masternodes informations for portchecker
    $sql = "SELECT inet6_ntoa(NodeIP) NodeIP, NodePort, NodeTestNet, NodePortCheck, NextCheck, NodeSubVer, ErrorMessage FROM cmd_portcheck ORDER BY NextCheck";
    $portcheck = array();
    if ($result = $mysqli->query($sql)) {
      while($row = $result->fetch_assoc()){
        $portcheck[] = $row;
      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => $portcheck));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// PORTCHECK (Reporting for dmnportcheck)
// ----------------------------------------------------------------------------
// End-point for the port check report
// HTTP method:
//   POST
// Parameters (JSON body):
//   array of portcheck information (mandatory)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/portcheck', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !is_array($payload) || (count($payload) == 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {

    $sqlpc = array();
    foreach($payload as $node) {
      $mngeoip = geoip_record_by_name($node['NodeIP']);
      if ($mngeoip !== FALSE) {
        $mnipcountry = $mngeoip["country_name"];
        $mnipcountrycode = strtolower($mngeoip["country_code"]);
      }
      else {
        $mnipcountry = "Unknown";
        $mnipcountrycode = "__";
      }
      $sqlpc[] = sprintf("(INET6_ATON('%s'),%d,%d,'%s','%s','%s','%s', '%s', '%s')",
          $mysqli->real_escape_string($node['NodeIP']),
                                  $node['NodePort'],
                                  $node['NodeTestNet'],
                                  $mysqli->real_escape_string($node['NodePortCheck']),
                                  $node['NextCheck'],
                                  $mysqli->real_escape_string($node['NodeSubVer']),
                                  $mysqli->real_escape_string($node['ErrorMessage']),
                                  $mysqli->real_escape_string($mnipcountry),
                                  $mysqli->real_escape_string($mnipcountrycode)
                                );
    }

    $sql = "INSERT INTO cmd_portcheck (NodeIP, NodePort, NodeTestNet, NodePortCheck, NextCheck, NodeSubVer, ErrorMessage, NodeCountry, NodeCountryCode)"
                           ." VALUES ".implode(',',$sqlpc)
            ." ON DUPLICATE KEY UPDATE NodePortCheck = VALUES(NodePortCheck), NextCheck = VALUES(NextCheck),"
            ." NodeSubVer = VALUES(NodeSubVer), ErrorMessage = VALUES(ErrorMessage), NodeCountry = VALUES(NodeCountry), NodeCountryCode = VALUES(NodeCountryCode)";

    if ($result = $mysqli->query($sql)) {
      $info = $mysqli->info;
      if (is_null($info)) {
        $info = true;
      }

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('portcheck' => $info)));

    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// THIRDPARTIES (Reporting for drkircbot)
// ----------------------------------------------------------------------------
// End-point to update third parties values (USD/DRK for ex)
// HTTP method:
//   POST
// Parameters (JSON body):
//   thirdparties=array of keys/values (mandatory)
//   dashwhale=array of keys/values (mandatory)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/thirdparties', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
      || !is_array($payload) || (count($payload) == 0)
      || !array_key_exists("thirdparties",$payload) || !is_array($payload["thirdparties"])
      || !array_key_exists("dashwhale",$payload) || !is_array($payload["dashwhale"])) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {

    $errors = array();

    // Third Parties values
    $sqlstats = array();
    foreach($payload["thirdparties"] as $key => $value) {
      $sqlstats[] = sprintf("('%s','%s',%d,'%s')",
                                  $mysqli->real_escape_string($key),
                                  $mysqli->real_escape_string($value['StatValue']),
                                  $value['LastUpdate'],
                                  $mysqli->real_escape_string($value['Source'])
                                );
    }

    if (count($sqlstats) > 0) {
            $sql = "INSERT INTO cmd_stats_values (StatKey, StatValue, LastUpdate, Source)"
              ." VALUES ".implode(',',$sqlstats)
              ." ON DUPLICATE KEY UPDATE StatValue = VALUES(StatValue), LastUpdate = VALUES(LastUpdate), Source = VALUES(Source)";

      if ($result = $mysqli->query($sql)) {
        $statsinfo = $mysqli->info;
        if (is_null($statsinfo)) {
          $statsinfo = true;
        }
      }
      else {
          $errors[] = "TP-".$mysqli->errno.': '.$mysqli->error;
      }
    }

    // Dash Whale data
    $sqldwc = array();
    foreach($payload["dashwhale"] as $proposal) {
      $dwinfo = var_export($proposal,true);
      if (is_array($proposal) && (count($proposal) == 2)
      && array_key_exists("proposal",$proposal) && is_array($proposal["proposal"])
      && array_key_exists("comments",$proposal) && is_array($proposal["comments"])
      && array_key_exists('hash',$proposal["proposal"]) && is_string($proposal["proposal"]["hash"])
      && (preg_match("/^[0-9a-f]{64}$/s", $proposal["proposal"]["hash"]) === 1)
      ){
        foreach($proposal["comments"] as $comment) {
            if ($comment !== false && is_array($comment) && array_key_exists('id', $comment) && is_string($comment["id"])
                && array_key_exists('username', $comment) && is_string($comment["username"])
                && array_key_exists('date', $comment) && is_string($comment["date"])
                && array_key_exists('order', $comment) && is_int($comment["order"])
                && array_key_exists('level', $comment)
                && array_key_exists('recently_posted', $comment) && is_bool($comment["recently_posted"])
                && array_key_exists('posted_by_owner', $comment) && is_bool($comment["posted_by_owner"])
                && array_key_exists('reply_url', $comment) && is_string($comment["reply_url"])
                && array_key_exists('content', $comment) && is_string($comment["content"])
                && (preg_match("/^[0-9a-f]{32}$/s", $comment["id"]) === 1)
                && (!filter_var($comment["reply_url"], FILTER_VALIDATE_URL) === false)
            ) {
                $sqldwc[] = sprintf("('%s','%s','%s','%s',%d,%d,%d,%d,'%s','%s')",
                    $mysqli->real_escape_string($proposal["proposal"]["hash"]),
                    $mysqli->real_escape_string($comment["id"]),
                    $mysqli->real_escape_string($comment["username"]),
                    $mysqli->real_escape_string($comment["date"]),
                    $comment["order"],
                    intval($comment["level"]),
                    $comment["recently_posted"] ? 1 : 0,
                    $comment["posted_by_owner"] ? 1 : 0,
                    $mysqli->real_escape_string($comment["reply_url"]),
                    $mysqli->real_escape_string($comment["content"])
                );
            }
        }
      }
    }

      if (count($sqldwc) > 0) {
          $sql = "INSERT INTO cmd_budget_dashwhale_comments (BudgetHash, CommentHash, CommentUsername, CommentDate, "
                ."CommentOrder, CommentLevel, CommentRecentPost, CommentByOwner, CommentReplyURL, CommentContent)"
                ." VALUES ".implode(',',$sqldwc)
                ." ON DUPLICATE KEY UPDATE CommentUsername = VALUES(CommentUsername), CommentDate = VALUES(CommentDate), "
                ." CommentOrder = VALUES(CommentOrder), CommentLevel = VALUES(CommentLevel), CommentRecentPost = VALUES(CommentRecentPost),"
                ." CommentByOwner = VALUES(CommentByOwner), CommentReplyURL = VALUES(CommentReplyURL), CommentContent = VALUES(CommentContent)";

          if ($result = $mysqli->query($sql)) {
              $dwinfo = $mysqli->info;
              if (is_null($dwinfo)) {
                  $dwinfo = true;
              }
          }
          else {
              $errors[] = "DW-".$mysqli->errno.': '.$mysqli->error;
          }
      }
      else {
          $dwinfo = "Nothing to do";
      }


    if (count($errors) == 0) {
        $response->setStatusCode(202, "Accepted");
        $response->setJsonContent(array('status' => 'OK', 'data' => array('thirdparties' => $statsinfo,
                                                                          'dashwhale' => $dwinfo)));
    }
    else {
        $response->setStatusCode(503, "Service Unavailable");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => $errors));
    }
  }

  return $response;

});

// ============================================================================
// VERSIONS
// ----------------------------------------------------------------------------
// End-point for creating new version of dashd to use by the nodes
// HTTP method:
//   POST
// Parameters (JSON body):
//   array of version parameters (mandatory)
// Result (JSON body):
//   status=OK|ERROR
//   messages=array of error messages (only if status is ERROR)
//   data=array of insert/update information (only if status is OK)
// ============================================================================
$app->post('/versions', function() use ($app,&$mysqli) {

  global $authinfo;

  //Create a response
  $response = new Phalcon\Http\Response();

  $payload = $app->request->getRawBody();
  $payload = json_decode($payload,true);

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) == 0)
   || !is_array($payload) || (count($payload) != 9)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {

    $sql = "INSERT INTO cmd_versions (VersionPath, VersionRaw, VersionDisplay, VersionTestnet, VersionEnabled, VersionURL, VersionSHA1, VersionSize, VersionHandling)"
          ." VALUES (".sprintf("'%s','%s','%s',%d,%d,'%s','%s',%d,%d",$payload['VersionPath'],
                                                                        $payload['VersionRaw'],
                                                                        $payload['VersionDisplay'],
                                                                        $payload['VersionTestnet'],
                                                                        $payload['VersionEnabled'],
                                                                        $payload['VersionURL'],
                                                                        $payload['VersionHash'],
                                                                        $payload['VersionSize'],
                                                                        $payload['VersionHandling'])
                  .")";

    if ($result = $mysqli->query($sql)) {
      $info = $mysqli->info;
      if (is_null($info)) {
        $info = true;
      }
      $versionid = $mysqli->insert_id;

      if ($payload['VersionTestnet'] == 1) {
        $onlytestnet = " AND NodeTestNet=1";
      }
      else {
        $onlytestnet = "";
      }
      $sql = sprintf("UPDATE cmd_nodes SET VersionID=%d WHERE KeepUpToDate=1$onlytestnet",$versionid);

      if ($result = $mysqli->query($sql)) {
        $info2 = $mysqli->info;
        if (is_null($info2)) {
          $info2 = true;
        }
      }
      else {
        $info2 = $mysqli->errno.': '.$mysqli->error;
      }

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('VersionId' => $versionid,
                                                                        "KeepUpToDate" => $info2)));

    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
    }
  }
  return $response;

});

// ============================================================================
// End-point not found
// ============================================================================
$app->notFound(function () use ($app) {
    $response = new Phalcon\Http\Response();
    $response->setStatusCode(404, "Not Found");
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Unknown end-point')));
    $response->send();
});

$request = new Phalcon\Http\Request();
$app->handle($request->getURI());

?>
