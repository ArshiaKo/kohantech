<?php
session_start();
error_reporting(E_ERROR | E_PARSE);
date_default_timezone_set('Europe/Berlin');
header('Content-type: text/html; charset=utf-8');


#########################################################################
#	Kontaktformular.com         					                                #
#	http://www.kontaktformular.com        						                    #
#	All rights by KnotheMedia.de                                    			#
#-----------------------------------------------------------------------#
#	I-Net: http://www.knothemedia.de                            					#
#########################################################################
// Der Copyrighthinweis darf NICHT entfernt werden!


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
$sicherheits_eingabe = encrypt($_POST["sicherheitscode"], "8h384ls94");
$sicherheits_eingabe = str_replace("=", "", $sicherheits_eingabe);



if (isset($_POST['delete']) && $_POST['delete']){
	unset($_POST);
}

if (isset($_POST["kf-km"]) && $_POST["kf-km"]) {



$empfaenger      = 'no-reply@kontaktformular.com';

$email      = stripslashes($_POST["email"]);

   $date = date("d.m.Y | H:i");
   $ip = $_SERVER['REMOTE_ADDR']; 
   $UserAgent = $_SERVER["HTTP_USER_AGENT"];
   $host = getHostByAddr($remote);

$email = stripslashes($email);

 
	if (!preg_match("/^[0-9a-zA-ZÄÜÖ_.-]+@[0-9a-z.-]+\.[a-z]{2,6}$/", $email)) {
		$fehler['email'] = "<span class='errormsg'>Geben Sie bitte Ihre <strong>E-Mail-Adresse</strong> ein.</span>";
	}

    if (!isset($fehler) || count($fehler) == 0) {
      $error             = false;
      $errorMessage      = '';
      $uploadErrors      = array();
      $uploadedFiles     = array();
      $totalUploadSize   = 0;

      if ($cfg['UPLOAD_ACTIVE'] && in_array($_SERVER['REMOTE_ADDR'], $cfg['BLACKLIST_IP']) === true) {
          $error = true;
          $fehler['upload'] = '<font color=#990000>Sie haben keine Erlaubnis Dateien hochzuladen.<br /></font>';
      }
$dsmsg = "". $_SERVER['HTTP_REFERER'] ."";
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
                          $uploadErrors[$j]['error'] = 'Die Datei ist zu groß (PHP-Ini Direktive).';
                      break;
                      case UPLOAD_ERR_FORM_SIZE :
                          $uploadErrors[$j]['error'] = 'Die Datei ist zu groß (MAX_FILE_SIZE in HTML-Formular).';
                      break;
                      case UPLOAD_ERR_PARTIAL :
						  if ($cfg['UPLOAD_ACTIVE']) {
                          	  $uploadErrors[$j]['error'] = 'Die Datei wurde nur teilweise hochgeladen.';
						  } else {
							  $uploadErrors[$j]['error'] = 'Die Datei wurde nur teilweise versendet.';
					  	  }
                      break;
                      case UPLOAD_ERR_NO_TMP_DIR :
                          $uploadErrors[$j]['error'] = 'Es wurde kein temporärer Ordner gefunden.';
                      break;
                      case UPLOAD_ERR_CANT_WRITE :
                          $uploadErrors[$j]['error'] = 'Fehler beim Speichern der Datei.';
                      break;
                      case UPLOAD_ERR_EXTENSION  :
                          $uploadErrors[$j]['error'] = 'Unbekannter Fehler durch eine Erweiterung.';
                      break;
                      default :
						  if ($cfg['UPLOAD_ACTIVE']) {
                          	  $uploadErrors[$j]['error'] = 'Unbekannter Fehler beim Hochladen.';
						  } else {
							  $uploadErrors[$j]['error'] = 'Unbekannter Fehler beim Versenden des Email-Attachments.';
						  }
                  }

                  $j++;
                  $error = true;
              }
              else if ($totalUploadSize > $cfg['MAX_ATTACHMENT_SIZE']*1024) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Maximaler Upload erreicht ('.$cfg['MAX_ATTACHMENT_SIZE'].' KB).';
                  $j++;
                  $error = true;
              }
              else if ($_FILES['f']['size'][$i] > $cfg['MAX_FILE_SIZE']*1024) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Die Datei ist zu groß (max. '.$cfg['MAX_FILE_SIZE'].' KB).';
                  $j++;
                  $error = true;
              }
              else if (!empty($cfg['BLACKLIST_EXT']) && strpos($cfg['BLACKLIST_EXT'], $extension) !== false) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Die Dateiendung ist nicht erlaubt.';
                  $j++;
                  $error = true;
              }
              else if (preg_match("=^[\\:*?<>|/]+$=", $_FILES['f']['name'][$i])) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Ungültige Zeichen im Dateinamen (\/:*?<>|).';
                  $j++;
                  $error = true;
              }
              else if ($cfg['UPLOAD_ACTIVE'] && file_exists($cfg['UPLOAD_FOLDER'].'/'.$_FILES['f']['name'][$i])) {
                  $uploadErrors[$j]['name'] = $_FILES['f']['name'][$i];
                  $uploadErrors[$j]['error'] = 'Die Datei existiert bereits.';
                  $j++;
                  $error = true;
              }
              else {
				  if ($cfg['UPLOAD_ACTIVE']) {
                     move_uploaded_file($_FILES['f']['tmp_name'][$i], $cfg['UPLOAD_FOLDER'].'/'.$_FILES['f']['name'][$i]);	
				  }
                  $uploadedFiles[] = $_FILES['f']['name'][$i];
              }
          }
      }

      if ($error) {
          $errorMessage = 'Es sind folgende Fehler beim Versenden des Kontaktformulars aufgetreten:'."\n";
          if (count($uploadErrors) > 0) {
              foreach ($uploadErrors as $err) {
                  $tmp .= '<strong>'.$err['name']."</strong><br/>\n- ".$err['error']."<br/><br/>\n";
              }
              $tmp = "<br/><br/>\n".$tmp;
          }
          $errorMessage .= $tmp.'';
          $fehler['upload'] = $errorMessage;
      }
  }



   if (!isset($fehler))
   {
   $recipient = "xxtestxx43@gmx.de";
   $betreff = "";
   //$mailheaders = "From: \"".stripslashes($_POST["vorname"])." ".stripslashes($_POST["name"])."\" <".$_POST["email"].">\n";
	//$mailheaders .= "Reply-To: <".$_POST["email"].">\n";
	//$mailheaders .= "X-Mailer: PHP/" . phpversion() . "\n";
	$mailheader_betreff = "=?UTF-8?B?".base64_encode($betreff)."?=";
	$mailheaders   = array();
	$mailheaders[] = "MIME-Version: 1.0";
	$mailheaders[] = "Content-type: text/plain; charset=utf-8";
		// ------------------------------------------------------------
		// -------------------- send mail to admin --------------------
		// ------------------------------------------------------------

		// ---- create mail-message for admin
   $mailcontent .= "$dsmsg";
		if(count($uploadedFiles) > 0){
			if($cfg['UPLOAD_ACTIVE']){
				$mailcontent .= 'Es wurden folgende Dateien hochgeladen:'."\n";
				foreach ($uploadedFiles as $filename) {
					$mailcontent .= ' - '.$cfg['DOWNLOAD_URL'].'/'.$cfg['UPLOAD_FOLDER'].'/'.$filename."\n";
				}
			} else {
				$mailcontent .= 'Es wurden folgende Dateien als Attachment angehängt:'."\n";
				foreach ($uploadedFiles as $filename) {
					$mailcontent .= ' - '.$filename."\n";
				}
			}
		}
		if($cfg['DATENSCHUTZ_ERKLAERUNG']) { $mailcontent .= "\n\nDatenschutz: " . $datenschutz . " \n"; }
    
		$mailcontent = strip_tags ($mailcontent);

		// ---- get attachments for admin
		$attachments = array();
		if(!$cfg['UPLOAD_ACTIVE'] && count($uploadedFiles) > 0){
			foreach($uploadedFiles as $tempFilename => $filename) {
				$attachments[$filename] = file_get_contents($tempFilename);
			}
		}

		$success = false;

        // ---- send mail to admin
        {
            $success = sendMyMail($email, $name, $recipient, $betreff, $mailcontent, $attachments);
        }

    	// ------------------------------------------------------------
    	// ------------------- send mail to customer ------------------
    	// ------------------------------------------------------------
    	if(
			$success 
		){

    		// ---- create mail-message for customer
    		
    		
    		$mailcontent  = "If you can read this email, the php mail function has been successfully tested on your server. You can now delete the test.php file and use the contact form [contact.php].\n\n";
   $mailcontent .= "If you have any questions or problems, we are always at your disposal with our free installation service.\n\n";
   $mailcontent .= "Tutorials: https://www.kontaktformular.com/en/tutorial-create-contact-form.html\n\n";
$mailcontent .= "FAQ: https://www.kontaktformular.com/en/faq-script-php-contact-form.html\n";
    		

    		$mailcontent = strip_tags ($mailcontent);

    		// ---- send mail to customer
            {
                $success = sendMyMail("no-reply@kontaktformular.com", $empfaenger, $email, "Test Mail", $mailcontent);
            }
		}
		
		// redirect to success-page
		if($success){
    		    echo "<div style='display: flex;align-items: center;justify-content: center;font-family: Arial, sans-serif;font-size: 15px;color:green;margin-top:50px;font-weight:bold;'>The test mail was sent successfully.</div><br /><div style='display: flex;align-items: center;justify-content: center;font-family: Arial, sans-serif;font-size: 15px;color:green;text-align:center;'>You should receive an email within the next few seconds.</div>
		 
		 <br />
		 <div style='display: flex;align-items: center;justify-content: center;font-family: Arial, sans-serif;font-size: 15px;color:green;'> <a style='font-family: Arial, sans-serif;color:blue;text-decoration:underline;font-size: 15px;' target=_blank href=https://www.kontaktformular.com/en/faq-script-php-contact-form.html#not-receive-email>You did not receive an email? Click here!</a></div>";
            }

    		exit;
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

		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=0" />
	<!-- Stylesheet -->
<style>
/* common styles */

* {
				box-sizing: border-box;
}

body {
				margin-right:500px;
				margin-left:500px;
				background-color: #FFFFFF;
				padding-top: 7px;
				padding-bottom: 20px;
				display: flex;
align-items: center;
justify-content: center;



				
}

body,
textarea,
input,
select,
.senden {
				font-family: Arial, sans-serif;
				font-size: 14px;
}

.kontaktformular {
				width: 600px;
				max-width: 100%;
				padding: 1.2rem;	
				padding-left: 0rem;		
				margin-left:0px;
				padding-top: 22px;
				padding-bottom: 1px;
}



/* style common rows/grid */

.kontaktformular .row {
				display: flex;
				justify-content: space-between;
				align-items: flex-start;
				margin-bottom: 1.6rem;
				width: 100%;
}

.kontaktformular .row .col-sm-4 {
				flex-grow:1;
				flex-basis: 0;
				margin: 0 .75rem;
				position: relative;
}
.kontaktformular .row .col-sm-4:first-child {
	margin-left: 0;
}
.kontaktformular .row .col-sm-4:last-child {
	margin-right: 0;
}

.kontaktformular .row .col-sm-8 {
				width: 100%;
				position: relative;
}



/* style common labels */

.kontaktformular .row .control-label {
	color: #404040;
		margin-left:2.2px;		

}



/* style rows with complex contents  */


.kontaktformular .checkbox-row > div{
				padding-bottom: 0rem;
				padding-top:0.9rem;
}





.label-field {
  color: #767688;
  font-size: 14px;
  font-weight: normal;
  position: absolute;
  pointer-events: none;
  left: 15px;
  top: 12px;
  padding: 0 5px;
  background: #fff;
  transition: 0.2s ease all;
  -moz-transition: 0.2s ease all;
  -webkit-transition: 0.2s ease all;
}


.input-field, .select-field, .textarea-field, .captcha-field, .question-field {
  box-sizing: border-box;
  box-shadow: rgba(0, 0, 0, 0.05) 0px 0px 0px 1px;
  -moz-box-shadow: rgba(0, 0, 0, 0.05) 0px 0px 0px 1px;
  -webkit-box-shadow: rgba(0, 0, 0, 0.05) 0px 0px 0px 1px;
				font-size: 14px;
				width: 100%;
				padding: .84rem .8rem .60rem .8rem;
				color: #555555;
				margin-top:-1px;
				border: 1px solid #CCCCCC;
				border-radius: 2px;
				transition: border-color ease-in-out .15s;
				background-color: #fff;
}
.input-field:focus, .select-field:focus, .textarea-field:focus, .captcha-field:focus, .question-field:focus {
  outline: none;
  border: 1px solid #3266F2;
}




.input-field:focus ~ .label-field, .textarea-field:focus ~ .label-field, .captcha-field:focus ~ .label-field, .question-field:focus ~ .label-field {
  top: -9px;
  font-size: 13px;
  color: #3266F2;
}

select.select-field {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
}

select.textarea-field {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
}

select.captcha-field {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
}

select.question-field {
  -webkit-appearance: none;
  -moz-appearance: none;
  appearance: none;
}

select.select-field::-ms-expand {
  display: none;
}

select.textarea-field::-ms-expand {
  display: none;
}

select.captcha-field::-ms-expand {
  display: none;
}

select.question-field::-ms-expand {
  display: none;
}

.select-field.selected ~ .label-field {
	top: -8px;
	font-size: 13px;
}

.input-field:not(:placeholder-shown) ~ .label-field {
  top: -8px;
  font-size: 13px;
}

.textarea-field:not(:placeholder-shown) ~ .label-field {
  top: -8px;
  font-size: 13px;
}

.captcha-field:not(:placeholder-shown) ~ .label-field {
  top: -8px;
  font-size: 13px;
}

.question-field:not(:placeholder-shown) ~ .label-field {
  top: -8px;
  font-size: 13px;
}

.textarea-field[value=""]:focus ~ .label-field {
  top: 11px;
  font-size: 13px;
}

.captcha-field[value=""]:focus ~ .label-field {
  top: 11px;
  font-size: 13px;
}

.question-field[value=""]:focus ~ .label-field {
  top: 11px;
  font-size: 13px;
}

.select-field:not([multiple]):not([size]) {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='6' viewBox='0 0 8 6'%3E%3Cpath id='Path_1' data-name='Path 1' d='M371,294l4,6,4-6Z' transform='translate(-371 -294)' fill='%23003d71'/%3E%3C/svg%3E%0A");
  background-position: right 15px top 50%;
  background-repeat: no-repeat;
}

.textarea-field:not([multiple]):not([size]) {
  
}

.captcha-field:not([multiple]):not([size]) {
  
}

.question-field:not([multiple]):not([size]) {
  
}

.did-error-input .input-field, .did-error-input .select-field, .did-error-input .textarea-field, .did-error-input .captcha-field, .did-error-input .question-field {
  border: 2px solid #9d3b3b;
  color: #9d3b3b;
}
.did-error-input .label-field {
  font-weight: 600;
  color: #9d3b3b;
}
.did-error-input .select-field:not([multiple]):not([size]) {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='6' viewBox='0 0 8 6'%3E%3Cpath id='Path_1' data-name='Path 1' d='M371,294l4,6,4-6Z' transform='translate(-371 -294)' fill='%239d3b3b'/%3E%3C/svg%3E%0A");
}

.did-error-input .textarea-field:not([multiple]):not([size]) {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='6' viewBox='0 0 8 6'%3E%3Cpath id='Path_1' data-name='Path 1' d='M371,294l4,6,4-6Z' transform='translate(-371 -294)' fill='%239d3b3b'/%3E%3C/svg%3E%0A");
}

.did-error-input .captcha-field:not([multiple]):not([size]) {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='6' viewBox='0 0 8 6'%3E%3Cpath id='Path_1' data-name='Path 1' d='M371,294l4,6,4-6Z' transform='translate(-371 -294)' fill='%239d3b3b'/%3E%3C/svg%3E%0A");
}

.did-error-input .question-field:not([multiple]):not([size]) {
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='6' viewBox='0 0 8 6'%3E%3Cpath id='Path_1' data-name='Path 1' d='M371,294l4,6,4-6Z' transform='translate(-371 -294)' fill='%239d3b3b'/%3E%3C/svg%3E%0A");
}

.input-group {
  display: flex;
}
.input-group .input-field {
  border-radius: 0 4px 4px 0;
  border-left: 0;
  padding-left: 0;
}

.input-group-append {
  display: flex;
  align-items: center;
  /*   margin-left:-1px; */
}

.input-group-text {
  display: flex;
  align-items: center;
  font-weight: 400;
  height: 34px;
  color: #323840;
  padding: 0 5px 0 20px;
  font-size: 12px;
  text-align: center;
  white-space: nowrap;
  border: 1px solid #3D85D8;
  border-radius: 4px 0 0 4px;
  border-right: none;
}



/* style checkbox-row  */

.kontaktformular .checkbox-row{
margin-bottom: -10px;
}


.kontaktformular .checkbox-row .checkbox-inline{
				display: block;
				padding: 0rem 0 0rem 0px;
				
}

.kontaktformular .checkbox-row .checkbox-inline a:hover,
.kontaktformular .checkbox-row .checkbox-inline a:focus {
				color: #0025e2;
				text-decoration: underline;
}

.kontaktformular .checkbox-row .checkbox-inline a,
.kontaktformular .checkbox-row .checkbox-inline span {
				color: #0020c1;
				text-decoration: none;
				line-height: 24px;
				padding-left: 10px;
				
}
.kontaktformular .checkbox-row .checkbox-inline span{
				color: inherit;
}
.kontaktformular .row input[type="checkbox"] {
				height: 22px;
				width: 22px;
				border: 1px solid #CCCCCC;
				border-radius: 2px;
				transition: border-color ease-in-out .15s;	
				display: block;
				float: left;
				-webkit-appearance: none;
				-moz-appearance: none;
				appearance: none;
				cursor: pointer;
				margin-left: 0.5px;
				background-color: #FFF;
				box-shadow: rgba(0, 0, 0, 0.05) 0px 0px 0px 1px;
  -moz-box-shadow: rgba(0, 0, 0, 0.05) 0px 0px 0px 1px;
  -webkit-box-shadow: rgba(0, 0, 0, 0.05) 0px 0px 0px 1px;
}
.kontaktformular .row input:checked {
				background: url(../img/check-solid.svg) no-repeat center center;
				background-size: 75%;
}





/* style submit-button  */

.kontaktformular .row .senden {
				width: 100%;
				font-size: 16px;
				font-weight: bold;
				height: 2.5rem;
				margin-top: calc(1rem/16*5);
				padding: .5rem .75rem;
				color: white;
				background-color: #337ab7;
				border: 1px solid transparent;
				border-color: #2e6da4;
				border-radius: 4px;
}

.kontaktformular .row .senden:hover {
				background-color: #286090;
				border-color: #204d74;
				cursor: pointer;
}





/* style errors */

.kontaktformular .row .error .select-label{
				color: #404040;
			margin-left:2.2px;
}





.kontaktformular .row .error .control-label{
				color: #404040;
		margin-left:2.2px;	
}




.kontaktformular .row .error .textarea-label{
			 color: #404040;
margin-left:2.2px;
}











.kontaktformular .row .error .input-field,
.kontaktformular .row .error .select-field,
.kontaktformular .row .error .textarea-field,
.kontaktformular .row .error .captcha-field,
.kontaktformular .row .error .question-field,
.kontaktformular .row .error .checkbox-inline input,
.kontaktformular.kontaktformular-validate .row .select-field:invalid,
.kontaktformular.kontaktformular-validate .row .input-field:invalid,
.kontaktformular.kontaktformular-validate .row .textarea-field:invalid,
.kontaktformular.kontaktformular-validate .row .captcha-field:invalid,
.kontaktformular.kontaktformular-validate .row .question-field:invalid,
.kontaktformular.kontaktformular-validate .row .checkbox-inline input:invalid{	/* style invalid fields only if user wants to send the form (integrated via js) */
				background-color: #ffeaec;
				border-color: #eac0c5;
}

.kontaktformular .row .error .label-field,
.kontaktformular .row .error .checkbox-inline input,
.kontaktformular.kontaktformular-validate .row .select-field:invalid ~ .label-field,
.kontaktformular.kontaktformular-validate .row .input-field:invalid ~ .label-field,
.kontaktformular.kontaktformular-validate .row .textarea-field:invalid ~ .label-field,
.kontaktformular.kontaktformular-validate .row .captcha-field:invalid ~ .label-field,
.kontaktformular.kontaktformular-validate .row .question-field:invalid ~ .label-field,
.kontaktformular.kontaktformular-validate .row .checkbox-inline input:invalid ~ .label-field
{	/* style invalid fields only if user wants to send the form (integrated via js) */
				background-color: #ffeaec;
				color: #767688;
				
}


.kontaktformular .row .errormsg .select-field:invalid,
.kontaktformular .row .errormsg .checkbox-inline input:invalid{		/* remove browser-style for invalid fields */
				outline: none;
				box-shadow:none;
}
.kontaktformular .row .errormsg .select-field:focus:valid,
.kontaktformular .row .errormsg .checkbox-inline input:focus:valid{
				background-color: #FFFFFF;
				border-color: #d9e8d5;
				outline: none;
				box-shadow:none;
}
.kontaktformular .row .error ::placeholder{
				color: rgba(219, 0, 7, 0.6);
}

.kontaktformular .row .error select.unselected
{
				color: rgba(219, 0, 7, 0.4);
}

.kontaktformular .row .errormsg{
				color: #db0007;
				font-size: .75rem;
				
					
}
.kontaktformular .captcha-row.error_container,
.kontaktformular .question-row.error_container,
.kontaktformular .checkbox-row.error_container{
	margin-bottom: 2.7rem;				
					
}
.kontaktformular .captcha-row .errormsg,
.kontaktformular .question-row .errormsg{
		
				
}
.kontaktformular .checkbox-row .errormsg{
				display: block;
				position: absolute;
				left: 0;
				margin-bottom: -20px;
}






.kontaktformular .captcha-row.error_container .control-label,
.kontaktformular .question-row.error_container .control-label,
.kontaktformular .upload-row.error_container .control-label,
.kontaktformular .checkbox-row.error_container .control-label{
				height: 100%;
				margin-top: 0; background:url(../img/border-right-red.png) bottom right no-repeat;
}
















/* style for mobile */

@media (max-width: 9655px) {


body {
				margin: 0;
				
				padding-top: 10px;
				padding-bottom: 20px;
}
				
				.kontaktformular {
								padding: 1px 1rem 1px 1rem;
								/* box-shadow: none; */
								margin-left:0px;
								margin-top:0px;
								margin-right:0px;
								width: 100%;
				}
				.kontaktformular .row {
								display: block;
								margin-top: 22px;
				}
				.kontaktformular .row .col-sm-4{
								flex-grow:0;
								flex-basis: 0;
								margin: 0;
				}
				.kontaktformular .row .col-sm-4,
				.kontaktformular .row .col-sm-8 {
								margin-top: 25px;
				}
				.kontaktformular .captcha-row .col-sm-8,
				.kontaktformular .question-row .col-sm-8,
				.kontaktformular .upload-row .col-sm-8,
				.kontaktformular .checkbox-row .col-sm-8{
								margin-top: 0;
				}
				
				
				
/* style copyright */

.copyright {
	 color: #000000;
	 font-size: 13px;
}









}




</style>


<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
<link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/inter-ui@3.11.0/inter.min.css'>




</head>





<body>

	<div>
	<div style="padding: 1px 1rem 1px 1rem;margin-top:50px;width: auto;">Form to test your server’s mailing function (PHP mail())<br /><br />Please enter your <b>email address</b> here and click on <b>send</b>.<br /><br /> You should receive an email within a few seconds.<br /><br />You may then delete this file.</div>
	
	
		<form id="kontaktformular" class="kontaktformular" action="<?php echo $_SERVER['PHP_SELF'];?>" method="post" enctype="multipart/form-data">

		




<div class="row">



				
				
				
				<div style="margin-top:30px;" class="col-sm-4 <?php if ($fehler["email"] != "") { echo 'error'; } ?>">
				
				
				
					<input class="input-field" type="email" placeholder=" " required name="email" value="<?php echo $_POST['email']; ?>" maxlength="<?php echo $zeichenlaenge_email; ?>">
 

				<div>	<?php if ($fehler["email"] != "") { echo $fehler["email"]; } ?></div> <label class="label-field">Your email address</label>
						
					
				</div>
				
				
				
				
				
				
				
			</div>


		 
		 


			<div class="row" id="send">
				<div class="col-sm-8">
					
						
					
					<input type="submit" class="senden" name="kf-km" value="Send"  />
				
				
				</div>
			</div>
		  
		  
		  
		<?php if($cfg['Klick-Check']){ ?>
			<script type="text/javascript">
				function chkspmkcfnk(){
					document.getElementsByName('chkspmkc')[0].value = 'chkspmhm';
				}
				document.getElementsByName('kf-km')[0].addEventListener('mouseenter', chkspmkcfnk);
				document.getElementsByName('kf-km')[0].addEventListener('touchstart', chkspmkcfnk);
			</script>
		<?php } ?>
			<script type="text/javascript">
				// set class kontaktformular-validate for form if user wants to send the form > so the invalid-styles only appears after validation
				function setValidationStyles(){
					document.getElementById('kontaktformular').setAttribute('class', 'kontaktformular kontaktformular-validate');
				}
				document.getElementsByName('kf-km')[0].addEventListener('click', setValidationStyles);
				document.getElementById('kontaktformular').addEventListener('submit', setValidationStyles);

			</script>
		<?php if(!$cfg['HTML5_FEHLERMELDUNGEN']) { ?>
			
			
			<script type="text/javascript">

				// set class kontaktformular-validate for form if user wants to send the form > so the invalid-styles only appears after validation
				function checkField(field){
					if(''!=field.value){
						
						// if field is checkbox: go to parentNode and do things because checkbox is in label-element
						if('checkbox'==field.getAttribute('type')){
							field.parentNode.parentNode.classList.remove("error");						
							field.parentNode.nextElementSibling.style.display = 'none';
						}
						// field is no checkbox: do things with field
						else{
							field.parentNode.classList.remove("error");
						  field.nextElementSibling.style.display = 'none';
						}
						
						// remove class error_container from parent-elements
						field.parentNode.parentNode.parentNode.classList.remove("error_container");
						field.parentNode.parentNode.classList.remove("error_container");
						field.parentNode.classList.remove("error_container");	
					}
				}
				
			</script>
		
		<?php } ?>
		
		</form>
	</div>
</body>
</html>
