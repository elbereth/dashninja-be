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
    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

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
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('TLS client certificate did not match a known hub')));
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
$router->setUriSource(\Phalcon\Mvc\Router::URI_SOURCE_SERVER_REQUEST_URI);

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
    $result = dashninja_cmd_getnodes($mysqli,$authinfo['HubId']);
    $numnodes = 0;
    $nodes = array();
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
$sqlkeep = $sql;
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
        $bisql[] = sprintf("(%d,%d,'%s','%s',%.9f,%.9f,%d,'%s',%d,%d,%.9f,%d,'%s',%.9f)",$bientry['BlockTestNet'],
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
                                                     $blockhist[intval($bientry['BlockId'])]['BlockMNValueRatioExpected']);
        if ((array_key_exists($bientry['BlockMNPayee'].":".$bientry['BlockTestNet'],$mninfo) && ($mninfo[$bientry['BlockMNPayee'].":".$bientry['BlockTestNet']] < $bientry['BlockId']))
         || !(array_key_exists($bientry['BlockMNPayee'].":".$bientry['BlockTestNet'],$mninfo))) {
          $mninfo[$bientry['BlockMNPayee'].":".$bientry['BlockTestNet']] = $bientry['BlockId'];
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
              ."BlockPoolPubKey, BlockMNProtocol, BlockTime, BlockDifficulty, BlockMNPayeeDonation, BlockMNPayeeExpected, BlockMNValueRatioExpected)"
              ." VALUES ".implode(',',$bisql)
              ." ON DUPLICATE KEY UPDATE BlockHash = VALUES(BlockHash), BlockMNPayee = VALUES(BlockMNPayee), BlockMNValue = VALUES(BlockMNValue),"
              ." BlockSupplyValue = VALUES(BlockSupplyValue), BlockMNPayed = VALUES(BlockMNPayed), BlockPoolPubKey = VALUES(BlockPoolPubKey),"
              ." BlockMNProtocol = VALUES(BlockMNProtocol), BlockTime = VALUES(BlockTime), BlockDifficulty = VALUES(BlockDifficulty),"
              ." BlockMNPayeeDonation = VALUES(BlockMNPayeeDonation), BlockMNPayeeExpected = VALUES(BlockMNPayeeExpected),"
              ." BlockMNValueRatioExpected = VALUES(BlockMNValueRatioExpected)";

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
        $biinfo = $sqlkeep;
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

      //Change the HTTP status
      $response->setStatusCode(202, "Accepted");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('blockshistory' => $bhinfo,
                                                                        'blocksinfo' => $biinfo,
                                                                        'mninfo' => $mninfoinfo)));

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
    if ($row !== false) {
      $protocol = $row['Protocol'];
    }
    else {
      $protocol = 0;
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
        $uniquemnips = $row['UniqueActiveMasternodesIPs'];
        $totalmncount = $row['ActiveMasternodesCount'];
        $curprotocol = $row['Protocol'];
      }
    }
  }
  else {
    $mninfo = false;
  }

  return $mninfo;

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

  if (!array_key_exists('CONTENT_LENGTH',$_SERVER) || (intval($_SERVER['CONTENT_LENGTH']) != 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");
    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload (or CONTENT_LENGTH) is missing')));
  }
  else {
    $mnlist1 = dashninja_masternodes_get($mysqli, 0);
    $mnlist1errno = $mysqli->errno;
    $mnlist1error = $mysqli->error;
    $mnlist2 = dashninja_masternodes_get($mysqli, 1);
    $mnlist2errno = $mysqli->errno;
    $mnlist2error = $mysqli->error;
    if (($mnlist1 !== false) && ($mnlist2 !== false)) {
      $mnlist = array_merge($mnlist1,$mnlist2);
    // Retrieve all known nodes for current hub
//    $sql = "SELECT inet_ntoa(cim.MasternodeIP) MasternodeIP, cim.MasternodePort MasternodePort, cim.MNTestNet MNTestNet, cimpk.MNPubKey MNPubKey FROM "
//          ."cmd_info_masternode cim, cmd_info_masternode_pubkeys cimpk WHERE "
//          ."cim.MasternodeIP = cimpk.MasternodeIP AND cim.MasternodePort = cimpk.MasternodePort AND cim.MNTestNet = cimpk.MNTestNet ORDER BY MasternodeIP, MasternodePort, MNTestNet, MNPubKey ";
//    $mnlist = array();
//    if ($result = $mysqli->query($sql)) {
//      while($row = $result->fetch_assoc()){
//        $mnlist[] = $row;
//      }

      //Change the HTTP status
      $response->setStatusCode(200, "OK");
      $response->setJsonContent(array('status' => 'OK', 'data' => array('masternodes' => $mnlist)));
    }
    else {
      $response->setStatusCode(503, "Service Unavailable");
      $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mnlist1errno.': '.$mnlist1error,$mnlist2errno.': '.$mnlist2error,print_r($mnlist1,true),print_r($mnlist2,true))));
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
    $sql = "SELECT NodeName, NodeTestNet, NodeEnabled, NodeType, VersionPath, VersionRaw, VersionDisplay, VersionHandling, KeepUpToDate FROM cmd_nodes n, cmd_hub_nodes h, cmd_versions v WHERE n.NodeId = h.NodeId AND n.VersionID = v.VersionID AND h.HubId = %d";
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

function dashninja_cmd_getnodes($mysqli,$hubid = -1) {

  $cachefnam = CACHEFOLDER.sprintf("dashninja_cmd_getnodes_%d",$hubid);
  $cachevalid = (is_readable($cachefnam) && ((filemtime($cachefnam)+3600)>=time()));
  if ($cachevalid) {
    $nodes = unserialize(file_get_contents($cachefnam));
  }
  else {
    $sql = "SELECT n.NodeId NodeId, NodeName, NodeTestNet, NodeEnabled, NodeType FROM cmd_nodes n, cmd_hub_nodes h WHERE n.NodeId = h.NodeId";
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
   || !array_key_exists('nodes',$payload)
   || !array_key_exists('stats',$payload) || !is_array($payload['stats'])
   || !array_key_exists('mninfo',$payload) || !is_array($payload['mninfo'])
   || !array_key_exists('mninfo2',$payload) || !is_array($payload['mninfo2'])
   || !array_key_exists('mnpubkeys',$payload) || !is_array($payload['mnpubkeys'])
   || !array_key_exists('mnbudgetshow',$payload) || !is_array($payload['mnbudgetshow'])
   || !array_key_exists('mnbudgetprojection',$payload) || !is_array($payload['mnbudgetprojection'])
   || !array_key_exists('mnlist',$payload) || !is_array($payload['mnlist'])
   || !array_key_exists('mnlist2',$payload) || !is_array($payload['mnlist2'])) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {
    // Retrieve all known nodes for current hub
    $nodes = dashninja_cmd_getnodes($mysqli,$authinfo['HubId']);
    $numnodes = count($nodes);
    if ($numnodes > 0) {
      if ($numnodes == count($payload['nodes'])) {
        $sqlstatus = array();
        $sqlspork = array();
        foreach($payload['nodes'] as $uname => $node) {
          if (!array_key_exists($uname,$nodes)) {
            $response->setStatusCode(503, "Service Unavailable");
            $response->setJsonContent(array('status' => 'ERROR', 'messages' => array("Unknown node reported")));
            return $response;
          }
          $sqlstatus[] = sprintf("(%d,'%s',%d,%d,%d,'%s',%d,inet_aton('%s'),%d,'%s','%s',NOW())",
                                  $nodes[$uname]['NodeId'],
                                  $mysqli->real_escape_string($node['ProcessStatus']),
                                  $node['Version'],
                                  $node['Protocol'],
                                  $node['Blocks'],
                                  $mysqli->real_escape_string($node['LastBlockHash']),
                                  $node['Connections'],
                                  $mysqli->real_escape_string($node['IP']),
                                  $node['Port'],
                                  $mysqli->real_escape_string($node['Country']),
                                  $mysqli->real_escape_string($node['CountryCode'])
                                );
          foreach($node['Spork'] as $sporkname => $sporkvalue) {
            $sqlspork[] = sprintf("(%d,'%s',%d)",
                                  $nodes[$uname]['NodeId'],
                                  $mysqli->real_escape_string($sporkname),
                                  $sporkvalue
                                 );
          }
        }

        $sql = "INSERT INTO cmd_nodes_status (NodeId, NodeProcessStatus, NodeVersion, NodeProtocol, NodeBlocks, NodeLastBlockHash,"
                                   ." NodeConnections, NodeIP, NodePort, NodeCountry, NodeCountryCode, LastUpdate)"
                           ." VALUES ".implode(',',$sqlstatus)
            ." ON DUPLICATE KEY UPDATE NodeProcessStatus = VALUES(NodeProcessStatus), NodeVersion = VALUES(NodeVersion),"
            ." NodeProtocol = VALUES(NodeProtocol), NodeBlocks = VALUES(NodeBlocks), NodeLastBlockHash = VALUES(NodeLastBlockHash),"
            ." NodeConnections = VALUES(NodeConnections), NodeIP = VALUES(NodeIP), NodePort = VALUES(NodePort), NodeCountry = VALUES(NodeCountry),"
            ." NodeCountryCode = VALUES(NodeCountryCode), LastUpdate = NOW()";

        if ($result = $mysqli->query($sql)) {
          $nodesinfo = $mysqli->info;

          $sql = "INSERT INTO cmd_nodes_spork (NodeID, SporkName, SporkValue) VALUE ".implode(',',$sqlspork)
                ." ON DUPLICATE KEY UPDATE SporkValue = VALUES(SporkValue)";
          $result = $mysqli->query($sql);
          $sporkinfo = $mysqli->info;

          $mninfosql = array();
          $mnqueryexc = array();
          $sqlpc = array();
          foreach($payload['mninfo'] as $mninfo) {
            $mniplong = ip2long($mninfo['MasternodeIP']);
            if ($mniplong !== false) {
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
              $sqlpc[] = sprintf("(%d, %d, %d, 'unknown', '%s', '%s')",
                                     $mniplong,
                                     $mninfo['MasternodePort'],
                                     $mninfo['MNTestNet'],
                                     $mnipcountry,
                                     $mnipcountrycode
                                    );
            }
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


          $mninfosql2 = array();
          $mnqueryexc2 = array();
          foreach($payload['mninfo2'] as $mninfo) {
            $mniplong = ip2long($mninfo['MasternodeIP']);
            if ($mniplong !== false) {
              $mnoutputhash = $mysqli->real_escape_string($mninfo['MasternodeOutputHash']);
              $mninfosql2[] = sprintf("('%s', %d, %d, %d, '%s', %d, %d, %d, %d, %d)",
                                      $mnoutputhash,
                                      $mninfo['MasternodeOutputIndex'],
                                      $mninfo['MasternodeTestNet'],
                                      $mninfo['MasternodeProtocol'],
                                      $mysqli->real_escape_string($mninfo['MasternodePubkey']),
                                      $mniplong,
                                      $mninfo['MasternodePort'],
                                      $mninfo['MasternodeLastSeen'],
                                      $mninfo['MasternodeActiveSeconds'],
                                      $mninfo['MasternodeLastPaid']
                                     );
//              $mnqueryexc2[] = sprintf("!(MasternodeOutputHash = '%s' AND MasternodeOutputIndex = %d AND MasternodeTestNet = %d)",$mnoutputhash,$mninfo['MasternodeOutputIndex'],$mninfo['MasternodeTestNet']);
              $mngeoip = geoip_record_by_name($mninfo['MasternodeIP']);
              if ($mngeoip !== FALSE) {
                 $mnipcountry = $mngeoip["country_name"];
                 $mnipcountrycode = strtolower($mngeoip["country_code"]);
              }
              else {
                 $mnipcountry = "Unknown";
                 $mnipcountrycode = "__";
              }
              $sqlpc[] = sprintf("(%d, %d, %d, 'unknown', '%s', '%s')",
                                     $mniplong,
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
                  ." MasternodeProtocol, MasternodePubkey, MasternodeIP, MasternodePort, MasternodeLastSeen,"
                  ." MasternodeActiveSeconds, MasternodeLastPaid) VALUE ".implode(',',$mninfosql2)
                  ." ON DUPLICATE KEY UPDATE MasternodeActiveSeconds = VALUES(MasternodeActiveSeconds),"
                  ." MasternodeLastSeen = VALUES(MasternodeLastSeen), MasternodeProtocol = VALUES(MasternodeProtocol),"
                  ." MasternodePubkey = VALUES(MasternodePubkey), MasternodeIP = VALUES(MasternodeIP),"
                  ." MasternodePort = VALUES(MasternodePort), MasternodeLastPaid = VALUES(MasternodeLastPaid)";
            $result22 = $mysqli->query($sql);
            $mninfo2info = $mysqli->info;
            unset($mninfosql2);
          }
          else {
            $mninfo2info = "Nothing to do";
          }

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

          $sql = "SELECT MasternodeIP, MasternodePort, MNTestNet, MNPubKey FROM cmd_info_masternode_pubkeys WHERE ".implode(' AND ',$mnpkexc)." AND MNLastReported != 0";
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

          $sql = "SELECT MasternodeIP, MasternodePort, MNTestNet, MNPubKey FROM cmd_info_masternode_donation WHERE ".implode(' AND ',$mndonationexc)." AND MNLastReported != 0";
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
          $sql = "SELECT MasternodeIP, MasternodePort, MNTestNet FROM cmd_info_masternode";
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

          $sql = "SELECT MasternodeOutputHash, MasternodeOutputIndex, MasternodeTestNet FROM cmd_info_masternode2";
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
          $networkhashps = array(0,0);
          $pricebtc = 0.0;
          $priceeuro = 0.0;
          $priceusd = 0.0;
          $testnetval = array();
          foreach($payload['stats'] as $testnet => $statarr) {
            $testnetval[] = $testnet;
            foreach($statarr as $statid => $statval) {
              if ($statid == "networkhashps") {
                $networkhashps[$testnet] = intval($statval);
              }
            }
          }
/*          $sql = "SELECT MNTestNet, COUNT(*) MNActive FROM "
                ."(SELECT cns.NodeProtocol NodeProtocol, ciml.MasternodeIP MasternodeIP, ciml.MasternodePort MasternodePort, ciml.MNTestNet MNTestNet, MNPubKey, COUNT(1) ActiveCount FROM "
                ."cmd_info_masternode_list ciml, cmd_info_masternode_pubkeys cimpk, cmd_nodes_status cns, (SELECT NodeTestNet, MAX(NodeProtocol) Protocol FROM "
                ."cmd_nodes cn, cmd_nodes_status cns WHERE cn.NodeId = cns.NodeId GROUP BY NodeTestnet) maxprot WHERE "
                ."ciml.MasternodeIP = cimpk.MasternodeIP AND ciml.MasternodePort = cimpk.MasternodePort AND ciml.MNTestNet = cimpk.MNTestNet AND "
                ."ciml.NodeID = cns.NodeID AND (MasternodeStatus = 'active' OR MasternodeStatus = 'current') AND cns.NodeProtocol = maxprot.protocol AND ciml.MNTestNet = maxprot.NodeTestNet "
                ."GROUP BY MasternodeIP, MasternodePort, MNTestNet, MNPubKey) mnactive WHERE ActiveCount > 0 GROUP BY MNTestNet";
*/
          $sql = "SELECT MNTestNet, COUNT(*) MNActive FROM "
                ."(SELECT cim.MasternodeOutputHash MasternodeOutputHash, cim.MasternodeOutputIndex MasternodeOutputIndex, cim.MasternodeTestNet MNTestNet, COUNT(1) ActiveCount FROM "
                ."cmd_info_masternode2_list ciml, cmd_info_masternode2 cim, (SELECT NodeTestNet, MAX(NodeProtocol) Protocol FROM "
                ."cmd_nodes cn, cmd_nodes_status cns WHERE cn.NodeId = cns.NodeId GROUP BY NodeTestnet) maxprot WHERE cim.MasternodeOutputHash = ciml.MasternodeOutputHash "
                ."AND ciml.MasternodeOutputIndex = cim.MasternodeOutputIndex AND ciml.MasternodeTestNet = cim.MasternodeTestNet AND (MasternodeStatus = 'active' OR MasternodeStatus = 'current') "
                ."AND cim.MasternodeProtocol = maxprot.Protocol AND ciml.MasternodeTestNet = maxprot.NodeTestNet "
                ."GROUP BY cim.MasternodeOutputHash, cim.MasternodeOutputIndex, cim.MasternodeTestNet) mnactive "
                ."WHERE ActiveCount > 0 GROUP BY MNTestNet";

          $sqlstats2 = array();
          $activemncount = 0;
          $activemncountarr[0] = 0;
          $activemncountarr[1] = 0;
          $uniquemnips = 0;
          drkmn_masternodes_count($mysqli,0,$activemncount,$uniquemnips);
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",'mnactive',$activemncount,time());
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",'mnuniqiptest',$uniquemnips,time());
          $activemncountarr[0] = $activemncount;
          $activemncount = 0;
          $uniquemnips = 0;
          drkmn_masternodes_count($mysqli,1,$activemncount,$uniquemnips);
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",'mnactivetest',$activemncount,time());
          $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",'mnuniqiptest',$uniquemnips,time());
          $activemncountarr[1] = $activemncount;

          $sql = "SELECT StatKey, StatValue FROM cmd_stats_values WHERE StatKey = 'usdbtc' OR StatKey = 'btcdrk' OR StatKey = 'eurobtc'";
          if ($result = $mysqli->query($sql)) {
            while ($row = $result->fetch_assoc()) {
              $tmp[$row['StatKey']] = floatval($row['StatValue']);
            }
            $result->free();
            $pricebtc = $tmp['btcdrk'];
            $priceeur = $pricebtc*$tmp['eurobtc'];
            $priceusd = $pricebtc*$tmp['usdbtc'];
          }

          foreach($testnetval as $testnet) {
            $sqlstats[] = sprintf("(%d,NOW(),%d,%d,%01.9f,%01.9f,%01.9f)",
                                       $testnet,
                                       $activemncount[$testnet],
                                       $networkhashps[$testnet],
                                       $pricebtc,
                                       $priceusd,
                                       $priceeur
                                  );
            $statkey = "networkhashpers";
            if ($testnet == 1) {
              $statkey .= "test";
            }
            $sqlstats2[] = sprintf("('%s','%s',%d,'dashninja')",$statkey,$networkhashps[$testnet],time());

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
//          $mnbudgetprojectioninfo = $sql."\n".$mysqli->error;

          //Change the HTTP status
          $response->setStatusCode(202, "Accepted");
          $response->setJsonContent(array('status' => 'OK', 'data' => array(
                                                                            'mnbudgetshow' => $mnbudgetshowinfo,
                                                                            'mnbudgetprojection' => $mnbudgetprojectioninfo,
                                                                            'mnlist' => $mnlistinfo,
                                                                            'mnlist2' => $mnlist2info,
                                                                            'mninfo' => $mninfoinfo,
                                                                            'mninfo2' => $mninfo2info,
                                                                            'mnpubkeys' => $mnpubkeysinfo,
                                                                            'mndonation' => $mndonationinfo,
                                                                            'mnvotes' => $mnvotesinfo,
                                                                            'nodes' => $nodesinfo,
                                                                            'portcheck' => $pcinfo,
                                                                            'spork' => $sporkinfo,
                                                                            'stats' => $statsinfo,
                                                                            'stats2' => $stats2info
                                                                           )));

        }
        else {
          $response->setStatusCode(503, "Service Unavailable");
          $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
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
// End-point to retrieve portcheck configuration
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
// End-point to retrieve portcheck list of nodes
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
    $sql = "SELECT inet_ntoa(NodeIP) NodeIP, NodePort, NodeTestNet, NodePortCheck, NextCheck, NodeSubVer, ErrorMessage FROM cmd_portcheck ORDER BY NextCheck";
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
      $sqlpc[] = sprintf("(%d,%d,%d,'%s','%s','%s','%s', '%s', '%s')",
                                  ip2long($node['NodeIP']),
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
   || !is_array($payload) || (count($payload) == 0)) {
    //Change the HTTP status
    $response->setStatusCode(400, "Bad Request");

    //Send errors to the client
    $response->setJsonContent(array('status' => 'ERROR', 'messages' => array('Payload is wrong or CONTENT_LENGTH is missing')));
  }
  else {

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

    var_dump($sql);


      if ($result = $mysqli->query($sql)) {
        $statsinfo = $mysqli->info;
        if (is_null($statsinfo)) {
          $statsinfo = true;
        }
        //Change the HTTP status
        $response->setStatusCode(202, "Accepted");
        $response->setJsonContent(array('status' => 'OK', 'data' => array('thirdparties' => $statsinfo)));
      }
      else {
        $response->setStatusCode(503, "Service Unavailable");
        $response->setJsonContent(array('status' => 'ERROR', 'messages' => array($mysqli->errno.': '.$mysqli->error)));
        return $response;
      }

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

$app->handle();

?>
