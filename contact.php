<?php
session_start();
error_reporting(E_ERROR | E_PARSE);
date_default_timezone_set('Europe/Berlin');
require_once("captcha/AntiSpam.php");
$q = AntiSpam::getRandomQuestion();
header('Content-type: text/html; charset=utf-8');


#########################################################################
#	Kontaktformular.com         					                                #
#	http://www.kontaktformular.com        						                    #
#	All rights by KnotheMedia.de                                    			#
#-----------------------------------------------------------------------#
#	I-Net: http://www.knothemedia.de                            					#
#########################################################################
// Do NOT remove the copyright notice!


  $script_root = substr(__FILE__, 0,
                        strrpos(__FILE__,
                                DIRECTORY_SEPARATOR)
                       ).DIRECTORY_SEPARATOR;

$remote = getenv("REMOTE_ADDR");

function encrypt($string, $key) {
	$result = '';
	for($i=0; $i<strlen($string); $i++) {
	   $char = substr($string, $i, 1);
	   $keychar = substr($key, ($i % strlen($key))-1, 1);
	   $char = chr(ord($char)+ord($keychar));
	   $result.=$char;
	}
	return base64_encode($result);
}

@require('config.php');
require_once("captcha/AntiSpam.php");
include("PHPMailer/Secureimage.php");
// form-data should be deleted
if (isset($_POST['delete']) && $_POST['delete']){
	unset($_POST);
}

// form has been sent
if (isset($_POST["en-us-kf-km"]) && $_POST["en-us-kf-km"]) {

	// clean data
	
	$name      	= stripslashes($_POST["name"]);
	$place		= stripslashes($_POST["place"]);
	$telephone		= stripslashes($_POST["telephone"]);
	$email      = stripslashes($_POST["email"]);
	$subject   	= stripslashes($_POST["subject"]);
	$message  = stripslashes($_POST["message"]);
	if($cfg['DATA_PRIVACY_POLICY']) { $data_protection = stripslashes($_POST["data_protection"]); }
	if($cfg['Security_code']){
		$sicherheits_eingabe = encrypt($_POST["sicherheitscode"], "8h384ls94");
		$sicherheits_eingabe = str_replace("=", "", $sicherheits_eingabe);
	}

	$date = date("d.m.Y | H:i");
	$ip = $_SERVER['REMOTE_ADDR'];
	$UserAgent = $_SERVER["HTTP_USER_AGENT"];
	$host = getHostByAddr($remote);


	// formcheck
	if(!$name) {
		$fehler['name'] = "<span class='errormsg'>Please enter your <strong>name</strong>.</span>";
	}
	
	if (!preg_match("/^[0-9a-zA-ZÄÜÖ_.-]+@[0-9a-z.-]+\.[a-z]{2,6}$/", $email)) {
		$fehler['email'] = "<span class='errormsg'>Please enter your <strong>email address</strong>.</span>";
	}
	
	if(!$subject) {
		$fehler['subject'] = "<span class='errormsg'>Please enter your <strong>subject</strong>.</span>";
	}
	
	if(!$message) {
		$fehler['message'] = "<span class='errormsg'>Please enter your <strong>message</strong>.</span>";
	}
	
	
	
	// -------------------- SPAMPROTECTION ERROR MESSAGES START ----------------------
	if($cfg['Security_code'] && $sicherheits_eingabe != $_SESSION['captcha_spam']){
		unset($_SESSION['captcha_spam']);
		$fehler['captcha'] = "<span class='errormsg'>The <strong>security code</strong> was wrong.</span>";
	} 
		

  if($cfg["Security_question"]){
	$answer = AntiSpam::getAnswerById(intval($_POST["q_id"]));
	if(isset($_POST["q"]) && $_POST["q"] != $answer){
		$fehler['q_id12'] = "<span class='errormsg'>Please answer the <strong>security question</strong> correctly.</span>";
	}
  }



	if($cfg['Honeypot'] && (!isset($_POST["mail"]) || ''!=$_POST["mail"])){
		$fehler['Honeypot'] = "<span class='errormsg'>Spam suspected. Please check your entries.</span>";
	}
	
	if($cfg['Time-out'] && (!isset($_POST["chkspmtm"]) || ''==$_POST["chkspmtm"] || '0'==$_POST["chkspmtm"] || (time() - (int) $_POST["chkspmtm"]) < (int) $cfg['Time-out'])){
		$fehler['Time-out'] = "<span class='errormsg'>Please wait a few seconds before submitting the form again.</span>";
	}
	
	if($cfg['Click_check'] && (!isset($_POST["chkspmkc"]) || 'chkspmhm'!=$_POST["chkspmkc"])){
		$fehler['Click_check'] = "<span class='errormsg'>Click the send button with the mouse to send the form.</span>";
	}
	
	if($cfg['Links'] < preg_match_all('#http(s?)\:\/\/#is', $message, $irrelevantMatches)){
		$fehler['Links'] = "<span class='errormsg'>Your message may ".(0==$cfg['Links'] ? 
																																'not contain any links ' : 
																																(1==$cfg['Links'] ? 
																																	'only one link' : 
																																	'a maximum of '.$cfg['Links'].' Links'
																																)
																															).".</span>";
	}
	
	if(''!=$cfg['Badwordfilter'] && 0!==$cfg['Badwordfilter'] && '0'!=$cfg['Badwordfilter']){
		$badwords = explode(',', $cfg['Badwordfilter']);			// the configured badwords
		$badwordFields = explode(',', $cfg['Badwordfields']);		// the configured fields to check for badwords
		$badwordMatches = array();									// the badwords that have been found in the fields
		
		if(0<count($badwordFields)){
			foreach($badwords as $badword){
				$badword = trim($badword);												// remove whitespaces from badword
				$badwordMatch = str_replace('%', '', $badword);							// take human readable badword for error-message
				$badword = addcslashes($badword, '.:/');								// make ., : and / preg_match-valid
				if('%'!=substr($badword, 0, 1)){ $badword = '\\b'.$badword; }			// if word mustn't have chars before > add word boundary at the beginning of the word
				if('%'!=substr($badword, -1, 1)){ $badword = $badword.'\\b'; }			// if word mustn't have chars after > add word boundary at the end of the word
				$badword = str_replace('%', '', $badword);								// if word is allowed in the middle > remove all % so it is also allowed in the middle in preg_match 
				foreach($badwordFields as $badwordField){
					if(preg_match('#'.$badword.'#is', $_POST[trim($badwordField)]) && !in_array($badwordMatch, $badwordMatches)){
						$badwordMatches[] = $badwordMatch;
					}
				}
			}		
			
			if(0<count($badwordMatches)){
				$fehler['Badwordfilter'] = "<span class='errormsg'>The following expressions are not allowed: ".implode(', ', $badwordMatches)."</span>";
			}
		}		
	}
  // -------------------- SPAMPROTECTION ERROR MESSAGES END ----------------------
  
  
	if($cfg['DATA_PRIVACY_POLICY'] && isset($data_protection) && $data_protection == ""){ 
		$fehler['data_protection'] = "<span class='errormsg'>You must accept the <strong>data privacy policy</strong>.</span>";
	}

	// there are NO errors > upload-check
    if (!isset($fehler) || count($fehler) == 0) {
      $error             = false;
      $errorMessage      = '';
      $uploadErrors      = array();
      $uploadedFiles     = array();
      $totalUploadSize   = 0;
	  $j = 0;
	  
	  
	  if (2==$cfg['UPLOAD_ACTIVE'] && in_array($_SERVER['REMOTE_ADDR'], $cfg['BLACKLIST_IP']) === true) {
          $error = true;
		  $uploadErrors[$j]['name'] = '';
          $uploadErrors[$j]['error'] = "You are not allowed to upload files.";
          $j++;
      }

      

      if (!$error) {
          for ($i=0; $i < $cfg['NUM_ATTACHMENT_FIELDS']; $i++) {
              if ($_FILES['f']['error'][$i] == UPLOAD_ERR_NO_FILE) {
                  continue;
              }

              $extension = explode('.', $_FILES['f']['name'][$i]);
              $extension = strtolower($extension[count($extension)-1]);
              $totalUploadSize += $_FILES['f']['size'][$i];

              if ($_FILES['f']['error'][$i] != UPLOAD_ERR_OK) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  switch ($_FILES['f']['error'][$i]) {
                      case UPLOAD_ERR_INI_SIZE :
                          $uploadErrors[$j]['error'] = 'The file is too large (PHP-Ini directive).';
                      break;
                      case UPLOAD_ERR_FORM_SIZE :
                          $uploadErrors[$j]['error'] = 'The file is too large (MAX_FILE_SIZE in HTML form).';
                      break;
                      case UPLOAD_ERR_PARTIAL :
						  if (2==$cfg['UPLOAD_ACTIVE']) {
                          	  $uploadErrors[$j]['error'] = 'The file was only partially uploaded.';
						  } else {
							  $uploadErrors[$j]['error'] = 'The file was only partially sent.';
					  	  }
                      break;
                      case UPLOAD_ERR_NO_TMP_DIR :
                          $uploadErrors[$j]['error'] = 'No temporary folder found.';
                      break;
                      case UPLOAD_ERR_CANT_WRITE :
                          $uploadErrors[$j]['error'] = 'Error while saving the file.';
                      break;
                      case UPLOAD_ERR_EXTENSION  :
                          $uploadErrors[$j]['error'] = 'Unknown error caused by an extension.';
                      break;
                      default :
						  if (2==$cfg['UPLOAD_ACTIVE']) {
                          	  $uploadErrors[$j]['error'] = 'Unknown error during upload.';
						  } else {
							  $uploadErrors[$j]['error'] = 'Unknown error when sending the email attachment.';
						  }
                  }

                  $j++;
                  $error = true;
              }
              if ($totalUploadSize > $cfg['MAX_ATTACHMENT_SIZE']*1024) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Maximum upload reached ('.$cfg['MAX_ATTACHMENT_SIZE'].' KB).';
                  $j++;
                  $error = true;
              }
              if ($_FILES['f']['size'][$i] > $cfg['MAX_FILE_SIZE']*1024) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'The file is too large (max. '.$cfg['MAX_FILE_SIZE'].' KB).';
                  $j++;
                  $error = true;
              }
              if (!empty($cfg['WHITELIST_EXT']) && strpos($cfg['WHITELIST_EXT'], $extension) === false) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'The file extension is not allowed.';
                  $j++;
                  $error = true;
              }
              if (preg_match("=^[\\:*?<>|/]+$=", $_FILES['f']['name'][$i])) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Invalid characters in the file name (\/:*?<>|).';
                  $j++;
                  $error = true;
              }
              if (2==$cfg['UPLOAD_ACTIVE'] && file_exists($cfg['UPLOAD_FOLDER'].'/'.$_FILES['f']['name'][$i])) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'The file already exists. Please change the file name.';
                  $j++;
                  $error = true;
              }
              if(!$error) {
				  if (2==$cfg['UPLOAD_ACTIVE']) {
                     move_uploaded_file($_FILES['f']['tmp_name'][$i], $cfg['UPLOAD_FOLDER'].'/'.$_FILES['f']['name'][$i]);
				  }
                  $uploadedFiles[$_FILES['f']['tmp_name'][$i]] = $_FILES['f']['name'][$i];
              }
          }
      }

      if ($error) {
          $errorMessage = 'The following errors occurred while sending the contact form:'."\n";
          if (count($uploadErrors) > 0) {
              $tmp = '';
			  foreach ($uploadErrors as $err) {
                  $tmp .= '<strong>'.$err['name']."</strong><br/>\n- ".$err['error']."<br/><br/>\n";
              }
              $tmp = "<br/><br/>\n".$tmp;
          }
          $errorMessage .= $tmp.'';
          $fehler['upload'] = "<span class='errormsg' style='display: block;'>".$errorMessage."</span>";
      }
	}


	// there are NO errors > send mail
   if (!isset($fehler))
   {
		// ------------------------------------------------------------
		// -------------------- send mail to admin --------------------
		// ------------------------------------------------------------

		// ---- create mail-message for admin
	  $mailcontent  = "You've received the following information through the contact form:\n" . "-------------------------------------------------------------------------\n\n";
		$mailcontent .= "Name: " . $name . "\n";
		$mailcontent .= "Email: " . $email . "\n\n";
		$mailcontent .= "Place: " . $place . "\n";
		$mailcontent .= "Telephone: " . $telephone . "\n";
		$mailcontent .= "\nSubject: " . $subject . "\n";
		$mailcontent .= "Message:\n" . $message = preg_replace("/\r\r|\r\n|\n\r|\n\n/","\n",$message) . "\n\n";
		if(count($uploadedFiles) > 0){
			if(2==$cfg['UPLOAD_ACTIVE']){
				$mailcontent .= "\n\n";
				$mailcontent .= 'The following files have been uploaded:'."\n";
				foreach ($uploadedFiles as $filename) {
					$mailcontent .= ' - '.$cfg['DOWNLOAD_URL'].'/'.$cfg['UPLOAD_FOLDER'].'/'.$filename."\n";
				}
			} else {
				$mailcontent .= "\n\n";
				$mailcontent .= 'The following files have been attached:'."\n";
				foreach ($uploadedFiles as $filename) {
					$mailcontent .= ' - '.$filename."\n";
				}
			}
		}
		if($cfg['DATA_PRIVACY_POLICY']) { $mailcontent .= "\n\nData protection: " . $data_protection . " \n"; }
    $mailcontent .= "\n\nIP address: " . $ip . "\n";
		$mailcontent = strip_tags ($mailcontent);

		// ---- get attachments for admin
		$attachments = array();
		if(1==$cfg['UPLOAD_ACTIVE'] && count($uploadedFiles) > 0){
			foreach($uploadedFiles as $tempFilename => $filename) {
				$attachments[$filename] = file_get_contents($tempFilename);
			}
		}

		$success = false;

        // ---- send mail to admin
        if($smtp['enabled'] !== 0) {
            require_once __DIR__ . '/smtp.php';
            $success = SMTP::send(
                $smtp['host'],
                $smtp['user'],
                $smtp['password'],
                $smtp['encryption'],
                $smtp['port'],
                $email,
                $yourname,
                $recipient,
                $subject,
                $mailcontent,
                (2==$cfg['UPLOAD_ACTIVE'] ? array() : $uploadedFiles),
                $cfg['UPLOAD_FOLDER'],
                $smtp['debug']
            );
        } else {
            $success = sendMyMail($email, $name, $recipient, $subject, $mailcontent, $attachments);
        }

    	// ------------------------------------------------------------
    	// ------------------- send mail to customer ------------------
    	// ------------------------------------------------------------
    	if(
			$success && 
			(
				2==$cfg['Send_copy'] || 																// send copy always
				(1==$cfg['Send_copy'] && isset($_POST['mail-copy']) && 1==$_POST['mail-copy'])		// send copy only if customer want to
			)
		){

    		// ---- create mail-message for customer
			$mailcontent  = "Many thanks for your email. We will answer as soon as possible.\n\n";
    		$mailcontent .= "Summary: \n" .  "-------------------------------------------------------------------------\n\n";
    		$mailcontent .= "Name: " . $name . "\n";
		$mailcontent .= "Email: " . $email . "\n\n";
		$mailcontent .= "Place: " . $place . "\n";
		$mailcontent .= "Telephone: " . $telephone . "\n";
		$mailcontent .= "\nSubject: " . $subject . "\n";
    		$mailcontent .= "Message:\n" . str_replace("\r", "", $message) . "\n\n";
    		if(count($uploadedFiles) > 0){
    			$mailcontent .= 'You have transferred the following files:'."\n";
    			foreach($uploadedFiles as $file){
    				$mailcontent .= ' - '.$file."\n";
    			}
    		}
    		$mailcontent = strip_tags ($mailcontent);

    		// ---- send mail to customer
            if($smtp['enabled'] !== 0) {
                SMTP::send(
                    $smtp['host'],
                    $smtp['user'],
                    $smtp['password'],
                    $smtp['encryption'],
                    $smtp['port'],
                    $recipient,
                    $yourname,
                    $email,
                    "Your request",
                    $mailcontent,
                    array(),
                    $cfg['UPLOAD_FOLDER'],
                    $smtp['debug']
                );
            } else {
                $success = sendMyMail($recipient, $yourname, $email, "Your request", $mailcontent);
            }
		}
		
		// redirect to success-page
		if($success){
			if($smtp['enabled'] === 0 || $smtp['debug'] === 0) {
    		    echo "<META HTTP-EQUIV=\"refresh\" content=\"0;URL=".$thankyou."\">";
            }

    		exit;
		}
		else{
			$fehler['Sendmail'] = "<span class='errormsg' style='display: block;'>The SMTP connection has failed.<br /><span style='text-decoration:underline;'>Possible reasons:</span><br />- Please check the information that you entered in the config.php file. <br />- If you want use an external mailserver (for example Yahoo), please contact your hosting provider for assistance. (Port forwarding is necessary)</span>";
		}
	}
}

// clean post
foreach($_POST as $key => $value){
    $_POST[$key] = htmlentities($value, ENT_QUOTES, "UTF-8");
}
?>
<?php




function sendMyMail($fromMail, $fromName, $toMail, $subject, $content, $attachments=array()){

	$boundary = md5(uniqid(time()));
	$eol = PHP_EOL;

	// header
	$header = "From: =?UTF-8?B?".base64_encode(stripslashes($fromName))."?= <".$fromMail.">".$eol;
	$header .= "Reply-To: <".$fromMail.">".$eol;
	$header .= "MIME-Version: 1.0".$eol;
	if(is_array($attachments) && 0<count($attachments)){
		$header .= "Content-Type: multipart/mixed; boundary=\"".$boundary."\"";
	}
	else{
		$header .= "Content-type: text/plain; charset=utf-8";
	}


	// content with attachments
	if(is_array($attachments) && 0<count($attachments)){

		// content
		$message = "--".$boundary.$eol;
		$message .= "Content-type: text/plain; charset=utf-8".$eol;
		$message .= "Content-Transfer-Encoding: 8bit".$eol.$eol;
		$message .= $content.$eol;

		// attachments
		foreach($attachments as $filename=>$filecontent){
			$filecontent = chunk_split(base64_encode($filecontent));
			$message .= "--".$boundary.$eol;
			$message .= "Content-Type: application/octet-stream; name=\"".$filename."\"".$eol;
			$message .= "Content-Transfer-Encoding: base64".$eol;
			$message .= "Content-Disposition: attachment; filename=\"".$filename."\"".$eol.$eol;
			$message .= $filecontent.$eol;
		}
		$message .= "--".$boundary."--";
	}
	// content without attachments
	else{
		$message = $content;
	}

	// subject
	$subject = "=?UTF-8?B?".base64_encode($subject)."?=";

	// send mail
	return mail($toMail, $subject, $message, $header);
}

?>
<!DOCTYPE html>
<html lang="de-DE">
	<head>
		<meta charset="utf-8">
		<meta name="language" content="de"/>
		<meta name="description" content="kontaktformular.com"/>
		<meta name="revisit" content="After 7 days"/>
		<meta name="robots" content="INDEX,FOLLOW"/>
		<title>kontaktformular.com</title>
		<link href="css/style-contact-form.css" rel="stylesheet" type="text/css" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0" />
	</head>
	<body id="Kontaktformularseite">
		<?php 
				if(
					(isset($fehler["Honeypot"]) && $fehler["Honeypot"] != "") || 
					(isset($fehler["Time-out"]) && $fehler["Time-out"] != "") ||
					(isset($fehler["Click_check"]) && $fehler['Click_check'] != "") ||
					(isset($fehler["Links"]) && $fehler['Links'] != "") ||
					(isset($fehler["Badwordfilter"]) && $fehler['Badwordfilter'] != "") || 
					(isset($fehler["Sendmail"]) && $fehler['Sendmail'] != "") ||
					(isset($fehler["upload"]) && $fehler['upload'] != "") 
				){
					?>
<div class="row">
					<label style="width:100%;"><?php if (isset($fehler["Honeypot"]) && $fehler["Honeypot"] != "") { echo $fehler["Honeypot"]; } ?>
							<?php if (isset($fehler["Time-out"]) && $fehler["Time-out"] != "") { echo $fehler["Time-out"]; } ?>
							<?php if (isset($fehler["Click_check"]) && $fehler["Click_check"] != "") { echo $fehler["Click_check"]; } ?>
							<?php if (isset($fehler["Links"]) && $fehler["Links"] != "") { echo $fehler["Links"]; } ?>
							<?php if (isset($fehler["Badwordfilter"]) && $fehler["Badwordfilter"] != "") { echo $fehler["Badwordfilter"]; } ?>
							<?php if (isset($fehler["Sendmail"]) && $fehler["Sendmail"] != "") { echo $fehler["Sendmail"]; } ?>
							<?php if (isset($fehler["upload"]) && $fehler["upload"] != "") { echo $fehler["upload"]; } ?></label>
					
				</div>
			<?php
		}
	
	
	?>	<form class="kontaktformular" action="<?php echo $_SERVER['PHP_SELF'];?>" method="post" enctype="multipart/form-data">
		
		
		
	


		
		
		
			<input type="hidden" name="action" value="smail" />
			<input type="hidden" name="content" value="formular"/>


					<div class="row column-2">
                    <div>
    					<label>Name: <span class="pflichtfeld">*</span></label>
    					<div class="field">
    						<?php if ($fehler["name"] != "") { echo $fehler["name"]; } ?><input type="text" name="name" maxlength="<?php echo $number_of_characters_name; ?>" value="<?php echo $_POST['name']; ?>"  <?php if ($fehler["name"] != "") { echo 'class="errordesignfields"'; } ?> <?php if($cfg['HTML5_error_messages']) { ?> required <?php } ?>/>

    					</div>
                    </div>
                    <div>
    					<label>Email: <span class="pflichtfeld">*</span></label>
    					<div class="field">
    						<?php if ($fehler["email"] != "") { echo $fehler["email"]; } ?><input type="text" name="email" maxlength="<?php echo $number_of_characters_email; ?>" value="<?php echo $_POST['email']; ?>"  <?php if ($fehler["email"] != "") { echo 'class="errordesignfields"'; } ?> <?php if($cfg['HTML5_error_messages']) { ?> required <?php } ?>/>

    					</div>
                    </div>
				</div>


				<div class="row column-2">
                    <div>
                        <label>Place: </label>
    					<div class="field">
    						<input type="text" name="place" maxlength="<?php echo $number_of_characters_ort; ?>" value="<?php echo $_POST['place']; ?>"  />

    					</div>
                    </div>
                    <div>
    					<label>Telephone: </label>
    					<div class="field">
    						<input type="text" name="telephone" maxlength="<?php echo $number_of_characters_telefon; ?>" value="<?php echo $_POST['telephone']; ?>"  />

    					</div>
                    </div>
				</div>


				 <div class="row">
					<label>Subject: <span class="pflichtfeld">*</span></label>
					<div class="field">
						<?php if ($fehler["subject"] != "") { echo $fehler["subject"]; } ?><input type="text" name="subject" style="width:100%;" maxlength="<?php echo $number_of_characters_betreff; ?>" value="<?php echo $_POST['subject']; ?>"  <?php if ($fehler["subject"] != "") { echo 'class="errordesignfields"'; } ?> <?php if($cfg['HTML5_error_messages']) { ?> required <?php } ?>/>

					</div>
				</div>


				<div class="row">
					<label>Message: <span class="pflichtfeld">*</span></label>
					<div class="field">
						<?php if ($fehler["message"] != "") { echo $fehler["message"]; } ?><textarea name="message"  cols="30" rows="8" <?php if ($fehler["message"] != "") { echo 'class="errordesignfields"'; } ?> <?php if($cfg['HTML5_error_messages']) { ?> required <?php } ?>><?php echo $_POST['message']; ?></textarea>

					</div>
				</div>


	<?php
			if(0<$cfg['NUM_ATTACHMENT_FIELDS']){
				echo '<div class="row">';
					echo '<label>File upload: </label>';
				echo '<div>';
				  for ($i=0; $i < $cfg['NUM_ATTACHMENT_FIELDS']; $i++) {
					  echo '<div><div class="field"><input type="file" style="margin-top:10px;" size="12" name="f[]" /></div></div></div></div>';
				  }

			}
			?>



<?php
// -------------------- SPAMPROTECTION START ----------------------

if($cfg['Honeypot']) { ?>

	<div style="height: 2px; overflow: hidden;">
		<label style="margin-top: 10px;">The following field must remain empty for the message to be sent!</label>
		<div style="margin-top: 10px;"><input type="email" name="mail" value="" /></div>
	</div>
<?php }

if($cfg['Time-out']){ ?>
	<input type="hidden" name="chkspmtm" value="<?php echo time(); ?>" />
<?php }

if($cfg['Click_check']){ ?>
	<input type="hidden" name="chkspmkc" value="chkspmbt" />
	
	
	
	<?php }
if($cfg['Security_code']) { ?>
  <div class="row" style="margin-top:40px;">
					<label>Security code:</label><br />
					<div class="field"><img src="captcha/captcha.php" alt="Security code" title="kontaktformular.com-sicherheitscode" id="captcha" />
						<a href="javascript:void(0);" onclick="javascript:document.getElementById('captcha').src='captcha/captcha.php?'+Math.random();cursor:pointer;">
							<span class="captchareload"><i style="color:grey;" class="fas fa-sync-alt"></i></span>
						</a>
					</div>
				</div>
 <div class="row" style="margin-top:10px;">
					<label>Please enter: <span class="pflichtfeld">*</span></label>

					
					<div class="field">
						<?php if ($fehler["captcha"] != "") { echo $fehler["captcha"]; } ?><input type="text" name="sicherheitscode" maxlength="150" value=""  <?php if ($fehler["captcha"] != "") { echo 'class="errordesignfields"'; } ?>/>

					</div>
				</div>
				
				
				
	<div class="row" style="margin-top:10px;">
<label></label>
<div class="field">

				<?php
if ($fehler) {
}
   else {
      print "Please enter security code.";
         }
?>

</div>
</div>

  

<?php }

if($cfg['Security_question']) { ?>
  

     <div class="row" style="margin-top:40px;">
					<label><?php echo $q[1]; ?>  <input type="hidden" name="q_id" value="<?php echo $q[0]; ?>"/></label>
					<div class="field">
					</div>
				</div>
 <div class="row" style="margin-top:80px;">
					<label>Please enter: <span class="pflichtfeld">*</span></label>

					
					<div class="field">
							<input type="text" <?php if ($fehler["q_id12"] != "") { echo 'class="errordesignfields"'; } ?> name="q"/>
<?php if ($fehler["q_id12"] != "") { echo $fehler["q_id12"]; } ?>

				<?php if ($fehler) { }   else {   print "";     } ?>

					</div>
				</div>
				
				
				
	<div class="row" style="margin-top:10px;">
<label></label>
<div class="field">

				<?php
if ($fehler) {
}
   else {
      print "Please answer this question to prevent spam.";
         }
?>

</div>
</div>
  
  


<?php } 

// -------------------- SPAMPROTECTION END ----------------------
		{ ?>






	<?php }
		
		// -------------------- MAIL-COPY START ----------------------

		if(1==$cfg['Send_copy']) { ?>
		<div class="row">
   <div class="checkbox-inline">
<input type=checkbox id="inlineCheckbox11" name="mail-copy" value="1" <?php if (isset($_POST['mail-copy']) && $_POST['mail-copy']=='1') echo(' checked="checked" '); ?> /> <span>Send a copy of the message by email</span></div></div>
			
	
	
<?php } 

		// -------------------- MAIL-COPY END ----------------------
		
		
		// -------------------- DATAPROTECTION START ----------------------

if($cfg['DATA_PRIVACY_POLICY']) { ?>


<div class="row">
   <div class="checkbox-inline">
<?php if ($fehler["data_protection"] != "") { echo $fehler["data_protection"]; } ?><input type=checkbox id="inlineCheckbox11" name="data_protection" value="accepted"<?php if ($_POST['data_protection']=='accepted') echo(' checked="checked" '); ?> <?php if($cfg['HTML5_error_messages']) { ?> required <?php } ?> /> <a href="<?php echo "$dataprivacypolicy"; ?>" target="_blank">I accept the data privacy policy.</a> *</div></div>







<?php } 

// -------------------- DATAPROTECTION END ----------------------
 ?>
 
 






<div class="pflichtfeldhinweis"><br /><b>Note:</b> Fields with <span class="pflichtfeld">*</span> are mandatory.</div>
			   <div class="buttons"><br /><input type="submit" name="en-us-kf-km" value="Send" style="width:100%;font-size:14px;" onclick="tescht();"/>
			  </div>


 
		
		<div class="copyright"><!-- Do NOT remove this copyright notice! --><br /><br /><a href="https://www.kontaktformular.com/en" title="kontaktformular.com">&copy; by kontaktformular.com - All rights reserved.</a></div>
		
		<?php if($cfg['Click_check']){ ?>
	<script type="text/javascript">
		function chkspmkcfnk(){
			document.getElementsByName('chkspmkc')[0].value = 'chkspmhm';
		}
		document.getElementsByName('en-us-kf-km')[0].addEventListener('mouseenter', chkspmkcfnk);
		document.getElementsByName('en-us-kf-km')[0].addEventListener('touchstart', chkspmkcfnk);
	</script>
<?php } ?>
		</form>
	</body>
</html>
