<?php
      $con = mysql_connect("localhost","sqli","sqli");
      if (!$con) {
        die('Could not connect: ' . mysql_error());
      }
      mysql_select_db("sqliexample", $con);
      $id = $_GET['id'];
      $result = mysql_query("SELECT name FROM user WHERE id=$id", $con);
    
      mysql_close($con);
      $num = mysql_num_rows($result);
      $i=0;
      while ($i < $num) {
        $name = mysql_result($result, $i, "name");
        echo "Hello " . $name;
        echo "<br/>";
        $i++;
      }
?>
