<?php
require_once('../../private/initialize.php');

// Until we learn about encryption, we will use an unencrypted
// master password as a stand-in. It should go without saying
// that this should *never* be done in real production code.
$master_password = 'secret';

// Set default values for all variables the page needs.
$errors = array();
$username = '';
$password = '';

if(is_post_request() && request_is_same_domain()) {
  ensure_csrf_token_valid();

  // Confirm that values are present before accessing them.
  if(isset($_POST['username'])) { $username = $_POST['username']; }
  if(isset($_POST['password'])) { $password = $_POST['password']; }

  // Validations
  if (is_blank($username)) {
    $errors[] = "Username cannot be blank.";
  }
  if (is_blank($password)) {
    $errors[] = "Password cannot be blank.";
  }


  if(!throttle_time($username) === 0){
      $errors[]= "Please wait " . ceil(throttle_time()). " before logging in again";
  }

  // If there were no errors, submit data to database
  if (empty($errors)) {
    $users_result = find_users_by_username($username);
    // No loop, only one result
    $user = db_fetch_assoc($users_result);
    if($user) {
      if(password_verify($password, $user['hashed_password'])) {
        // Username found, password matches
        log_in_user($user);
        $failed_login = [
            'username' => $username,
            'count' => 0,
            'last_attempt' => date("Y-m-d H:i:s")
          ];
        update_failed_login($failed_login);
        // Redirect to the staff menu after login
        redirect_to('index.php');
      } else {
        // Username found, but password does not match.
        $errors[] = "Log in was unsuccessful.";
        record_failed_login($username);
      }
    } else {
      // No username found
      $errors[] ="Log in was unsuccessful.";
      record_failed_login($username);
    }
  }
}

?>

<?php
  //
  // Failed Login Queries
  //
  function find_failed_login($username=""){
    global $db;
    $sql ="SELECT * FROM failed_logins ";
    $sql .= "WHERE username='" . db_escape($db, $username) . "';";
    $result = db_query($db, $sql);
    return $result;
  }

  function insert_failed_login($fl){
    global $db;
    $sql = "INSERT INTO `failed_logins` (`username`,`count`,`last_attempt`) VALUES ('";
    $sql .= db_escape($db, $fl['username']);
    $sql .= "', '";
    $sql .= db_escape($db, $fl['count']);
    $sql .= "', '";
    $sql .= db_escape($db, $fl['last_attempt']);
    $sql .= "')";
    $result = db_query($db, $sql);
    if($result) {
      return true;
    } else {
      // The SQL INSERT statement failed.
      // Just show the error, not the form
      echo db_error($db);
      db_close($db);
      exit;
    }
  }

  function update_failed_login($fl){
      global $db;
      $id = db_escape($db, $fl['id']);
      $sql = "UPDATE `failed_logins` SET ";
      $sql .= "count='";
      $sql .= db_escape($db, $fl['count']) . "', ";
      $sql .= "last_attempt='" . $failed_login['last_attempt'] . "' ";
      $sql .= "WHERE username='" . db_escape($db, $failed_login['username']) . "' ";
      $sql .= "LIMIT 1;";
      $result = db_query($db, $sql);
      if($result) {
        return true;
      } else {
        // The SQL UPDATE statement failed.
        // Just show the error, not the form
        echo db_error($db);
        db_close($db);
        exit;
      }
  }

    function record_failed_login($username) {
      // The failure technically already happened, so
      // get the time ASAP.
      $sql_date = date("Y-m-d H:i:s");

      $fl_result = find_failed_login($username);
      $failed_login = db_fetch_assoc($fl_result);

      if(!$failed_login) {
        $failed_login = [
          'username' => $username,
          'count' => 1,
          'last_attempt' => $sql_date
        ];
        insert_failed_login($failed_login);
      } else {
        $failed_login['count'] = $failed_login['count']++;
        $failed_login['last_attempt'] = $sql_date;
        update_failed_login($failed_login);
      }
      return true;
    }

  function throttle_time($username) {
      $threshold = 10;
      $lockout = 60 * 10; // in seconds
      $fl_result = find_failed_login($username);
      $failed_login = db_fetch_assoc($fl_result);
      if(!isset($failed_login)) { return 0; }
      if($failed_login['count'] < $threshold) { return 0; }
      $last_attempt = strtotime($failed_login['last_attempt']);
      $since_last_attempt = time() - $last_attempt;
      $remaining_lockout = $lockout - $since_last_attempt;
      if($remaining_lockout < 0) {
        reset_failed_login($username);
        return 0;
      } else {
        return $remaining_lockout;
      }
  }
?>

<?php $page_title = 'Log in'; ?>
<?php include(SHARED_PATH . '/header.php'); ?>
<div id="menu">
  <ul>
    <li><a href="../index.php">Public Site</a></li>
  </ul>
</div>

<div id="main-content">
  <h1>Log in</h1>

  <?php echo display_errors($errors); ?>

  <form action="login.php" method="post">
    <?php echo csrf_token_tag(); ?>
    Username:<br />
    <input type="text" name="username" value="<?php echo h($username); ?>" /><br />
    Password:<br />
    <input type="password" name="password" value="" /><br />
    <input type="submit" id="submitbtn" name="submit" value="Submit"  />
  </form>

</div>

<?php include(SHARED_PATH . '/footer.php'); ?>
