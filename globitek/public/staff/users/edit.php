<?php
require_once('../../../private/initialize.php');
require_login();

if(!isset($_GET['id'])) {
  redirect_to('index.php');
}
$users_result = find_user_by_id($_GET['id']);
// No loop, only one result
$user = db_fetch_assoc($users_result);

// Set default values for all variables the page needs.
$errors = array();

if(is_post_request() && request_is_same_domain()) {
  ensure_csrf_token_valid();

  // Confirm that POST values are present before accessing them.
    if(isset($_POST["first_name"])){
      $user['first_name'] = sanitize_input($_POST["first_name"]);
    }
    if(isset($_POST["last_name"])){
      $user['last_name'] = sanitize_input($_POST["last_name"]);
    }
    if(isset($_POST["username"])){
      $user['username'] = sanitize_input($_POST["username"]);
    }
    if(isset($_POST["email"])){
      $user['email'] = sanitize_input($_POST["email"]);
    }
    if(isset($_POST["password"])){
      $password = sanitize_input($_POST["password"]);
    }
    if(isset($_POST["confirm_password"])){
      $confirm_password = sanitize_input($_POST["confirm_password"]);
    }

    // Perform Validations
    // Hint: Write these in private/validation_functions.php
    if(is_blank($user['first_name'])){
      $errors[] = "Firstname cannot be blank";
    }
    if(is_blank($user['last_name'])){
      $errors[] = "Lastname cannot be blank";
    }
    if(is_blank($user['username'])){
      $errors[] = "Username cannot be blank";
    }
    if(is_blank($user['email'])){
      $errors[] = "email cannot be blank";
    }
    if(is_blank($password)){
      $errors[] = "Password cannot be blank";
    }

    if(!has_valid_email_format($user['email'])){
      $errors[] = "Invalid email";
    }
    if(!has_valid_username_format($user['username'])){
      $errors[] = "Invalid Username";
    }
    if(!has_length($user['first_name'], array('min'=> 1, 'max'=>255))){
      $errors[] = "Firstname must be less than 255 characters";
    }
    if(!has_length($user['last_name'], array('min'=> 1, 'max'=>255))){
      $errors[] = "Lastname must be less than 255 characters";
    }
    if(!has_length($user['username'], array('min'=> 1, 'max'=>255))){
      $errors[] = "Username must be less than 255 characters";
    }
    if(!has_length($user['email'], array('min'=> 1, 'max'=>255))){
      $errors[] = "email must be less than 255 characters";
    }
    if(!has_length($password, array('min'=> 12, 'max'=>255))){
      $errors[] = "Password must be between 12 and 255 characters";
    }
    if(!has_valid_password($password)){
      $errors[] = "Password random is invalid";
    }
    if(strcmp($password, $confirm_password) !== 0){
      $errors[] = "Passwords do not match";
    }


  // if there were no errors, submit data to database
  if(empty($errors)){
      // Encryption/Hashing
      $user['hashed_password'] = password_hash($password, PASSWORD_BCRYPT);
      $result = update_user($user);
      if($result === true) {
        redirect_to('show.php?id=' . $user['id']);
      } else {
        $errors = $result;
      }
  }
}
?>
<?php $page_title = 'Staff: Edit User ' . $user['first_name'] . " " . $user['last_name']; ?>
<?php include(SHARED_PATH . '/staff_header.php'); ?>

<div id="main-content">
  <a href="index.php">Back to Users List</a><br />

  <h1>Edit User: <?php echo h($user['first_name']) . " " . h($user['last_name']); ?></h1>

  <?php echo display_errors($errors); ?>

  <form action="edit.php?id=<?php echo h(u($user['id'])); ?>" method="post">
    <?php echo csrf_token_tag(); ?>
    First name:<br />
    <input type="text" name="first_name" value="<?php echo h($user['first_name']); ?>" /><br />
    Last name:<br />
    <input type="text" name="last_name" value="<?php echo h($user['last_name']); ?>" /><br />
    Username:<br />
    <input type="text" name="username" value="<?php echo h($user['username']); ?>" /><br />
    Email:<br />
    <input type="text" name="email" value="<?php echo h($user['email']); ?>" /><br />
    <br />
    <input type="submit" name="submit" value="Update"  />
  </form>

</div>

<?php include(SHARED_PATH . '/footer.php'); ?>
