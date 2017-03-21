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
      $user['password'] = sanitize_input($_POST["password"]);
    }
    if(isset($_POST["confirm_password"])){
      $user['confirm_password'] = sanitize_input($_POST["confirm_password"]);
    }
    if(isset($_POST["previous_password"])){
      $user['previous_password'] = sanitize_input($_POST["previous_password"]);
    }
    // Encryption/Hashing
    if(!is_blank($user['password'])){
      $user['hashed_password'] = password_hash($user['password'], PASSWORD_BCRYPT);
    }
    $result = update_user($user);
    if($result === true) {
      redirect_to('show.php?id=' . $user['id']);
    } else {
      $errors = $result;
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
    <br/>Previous Password:<br />
    <input type="password" name="previous_password"/><br />
    <br />
    Passwords should be at least 12 characters and include at least one uppercase letter, lowercase letter, number, and symbol.
    <br/>Password:<br />
    <input type="password" name="password"/><br />
    <br />
    Confirm Password:<br />
    <input type="password" name="confirm_password"/><br />
    <br />
    <input type="submit" name="submit" value="Update"  />
  </form>

</div>

<?php include(SHARED_PATH . '/footer.php'); ?>
