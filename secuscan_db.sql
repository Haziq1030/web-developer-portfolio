-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Aug 19, 2026 at 05:56 AM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `secuscan_db`
--

-- --------------------------------------------------------

--
-- Table structure for table `file_scan_logs`
--

CREATE TABLE `file_scan_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `filename` varchar(255) NOT NULL,
  `file_hash` varchar(64) NOT NULL,
  `hasil_pemeriksaan` varchar(50) NOT NULL,
  `tahap_ketepatan` varchar(10) NOT NULL,
  `tujuan` varchar(50) NOT NULL DEFAULT 'Personal',
  `tarikh_semak` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `file_scan_logs`
--

INSERT INTO `file_scan_logs` (`id`, `user_id`, `filename`, `file_hash`, `hasil_pemeriksaan`, `tahap_ketepatan`, `tarikh_semak`) VALUES
(1, NULL, '13DIT24F1171.pdf', 'acfcafff6aa4ab0d4201cc89f53eda50226c78df9e30a358750a3ba983c4075c', 'Safe', '99.90%', '2026-07-27 15:27:10'),
(2, NULL, '13DIT24F1171.pdf', 'acfcafff6aa4ab0d4201cc89f53eda50226c78df9e30a358750a3ba983c4075c', 'Safe', '99.90%', '2026-07-27 15:30:00'),
(3, NULL, 'Isi_Kandungan_1_Page(1)(1).pdf', '043524f0bf10c23706ba202d1e1c2a8e14eb83c9f15bbc792c0c96180128a79d', 'Safe', '99.90%', '2026-07-28 09:54:23'),
(4, NULL, 'eicar_virus.txt.txt', 'c:\\xampp\\htdocs\\secu scan\\uploads\\1785232615_eicar_virus.txt.txt', 'Malware Detected', '99.90%', '2026-07-28 09:56:55'),
(5, NULL, 'eicar_virus.txt.txt', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'Malware Detected', '99.90%', '2026-07-28 10:24:24'),
(6, NULL, 'eicar_virus.txt.txt', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'Malware Detected', '99.90%', '2026-07-28 10:24:34'),
(7, NULL, 'eicar.txt', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'Malware Detected', '99.90%', '2026-07-29 11:35:15'),
(8, NULL, 'PWORK1 DFK50083_SET2 AKMAL HAZIQ 13DIT24F1140.pdf', '388db7d6ef2cda77f754d984be37a92097a4602891324633b5da15a4d48f6e7e', 'Safe', '99.90%', '2026-07-29 11:35:32'),
(9, NULL, 'PWORK1 DFK50083_SET2 AKMAL HAZIQ 13DIT24F1140.pdf', '388db7d6ef2cda77f754d984be37a92097a4602891324633b5da15a4d48f6e7e', 'Safe', '99.90%', '2026-07-29 11:36:46'),
(10, NULL, 'Akmal_Haziq_13dit24F1140.pdf', '9c09de8fce78b52eda992f776b8fae01e39b39e6fdb05e12c04c09441831e820', 'Safe', '99.90%', '2026-07-29 11:37:21'),
(11, NULL, 'Akmal_Haziq_13dit24F1140.pdf', '9c09de8fce78b52eda992f776b8fae01e39b39e6fdb05e12c04c09441831e820', 'Safe', '99.90%', '2026-08-04 17:49:37'),
(12, NULL, 'Akmal_Haziq_13dit24F1140.pdf', '9c09de8fce78b52eda992f776b8fae01e39b39e6fdb05e12c04c09441831e820', 'Safe', '99.90%', '2026-08-04 18:01:35'),
(13, NULL, 'Akmal_Haziq_13dit24F1140.pdf', '9c09de8fce78b52eda992f776b8fae01e39b39e6fdb05e12c04c09441831e820', 'Safe', '99.90%', '2026-08-04 18:01:45'),
(14, NULL, 'Akmal_Haziq_13dit24F1140.pdf', '9c09de8fce78b52eda992f776b8fae01e39b39e6fdb05e12c04c09441831e820', 'Safe', '99.90%', '2026-08-04 18:04:25'),
(15, NULL, 'Akmal_Haziq_13dit24F1140.pdf', '9c09de8fce78b52eda992f776b8fae01e39b39e6fdb05e12c04c09441831e820', 'Safe', '99.90%', '2026-08-05 07:26:29'),
(16, NULL, 'skor kiar.jpeg', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Safe', '99.90%', '2026-08-05 07:28:27'),
(17, NULL, 'Book1.xlsx', '8e56ad4f97587fc6e66341321ab5816d92fcc1f131648a7ff169ef2d7ad85eb2', 'Safe', '99.90%', '2026-08-05 07:29:02'),
(18, NULL, 'PW2-Student Copy.zip', 'b56995d911c2c68c6bae2f70ca4e69fc6073f30bddb5ba0cef34ce76ea7541e1', 'Safe', '99.90%', '2026-08-05 07:30:42'),
(19, NULL, 'JCreator.exe', '8be923e254ad48a0f3040b8d06f790ed013d15b75cf33a6f2d03f7bf0a3956ad', 'Safe', '99.90%', '2026-08-05 07:32:08'),
(20, NULL, 'thonny.exe', 'bab31d2fffa03bf56f058176a0cafaa53c3accf96c07024b5a5d5eb900588719', 'Safe', '99.90%', '2026-08-05 07:32:29'),
(21, NULL, '2.jpg', '19b7600d0b3e72f1548cf96ef3731f11f975db764a2631f3183c8c79695ee831', 'Safe', '99.90%', '2026-08-19 03:11:39');

-- --------------------------------------------------------

--
-- Table structure for table `scan_logs`
--

CREATE TABLE `scan_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `url` varchar(255) NOT NULL,
  `hasil_pemeriksaan` varchar(50) NOT NULL,
  `tahap_ketepatan` varchar(10) NOT NULL,
  `tujuan` varchar(50) NOT NULL DEFAULT 'Personal',
  `tarikh_semak` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `scan_logs`
--

INSERT INTO `scan_logs` (`id`, `user_id`, `url`, `hasil_pemeriksaan`, `tahap_ketepatan`, `tarikh_semak`) VALUES
(1, NULL, 'https://www.google.com](https://www.google.com', 'Safe', '91.57%', '2026-07-28 10:25:26'),
(2, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-28 10:25:40'),
(3, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-28 10:27:43'),
(4, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 04:30:54'),
(5, NULL, 'https://www.google.com](https://www.google.com', 'Safe', '91.57%', '2026-07-29 04:31:21'),
(6, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-07-29 11:22:32'),
(7, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:37:45'),
(8, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:40:02'),
(9, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:40:34'),
(10, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:42:41'),
(11, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:47:31'),
(12, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:49:55'),
(13, NULL, 'http://login-verification-bank-security.com](http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-07-29 11:53:48'),
(14, NULL, 'http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-08-04 17:49:54'),
(15, NULL, 'http://login-verification-bank-security.com', 'Phishing', '91.57%', '2026-08-04 17:49:54'),
(16, NULL, 'https://www.google.com](https://www.google.com', 'Safe', '91.57%', '2026-08-04 18:01:24'),
(17, NULL, 'http://login-maybank2u-update-security-account.com/login@verify-user', 'Phishing', '91.57%', '2026-08-04 18:02:04'),
(18, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-04 18:04:16'),
(19, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-05 06:52:15'),
(20, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-05 06:54:24'),
(21, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-05 07:24:37'),
(22, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-05 07:43:05'),
(23, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-05 07:50:50'),
(24, NULL, 'http://cimbclicks-scam-update-web.net', 'Phishing', '91.57%', '2026-08-19 03:10:58');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) NOT NULL,
  `is_admin` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password`, `is_admin`, `created_at`) VALUES
(1, 'admin', 'admin@secuscan.com', '0192023a7bbd73250516f069df18b500', 1, '2026-08-04 17:56:09'),
(2, 'akmal', 'akmalhaziq1030@gmail.com', '$2y$10$EDasxdUyogTHpLNAm62hnum1zfD2IIR8ztS4nB73xbl2d2kS0NuZ6', 0, '2026-08-04 18:00:47'),
(4, 'faqrul', 'nishmal088@gmail.com', '$2y$10$v5O2PN6FbrTAnlUGA68Kl.QPr2lmM4SnBZJhrwRZcimBffgRxbOCW', 0, '2026-08-19 03:24:43');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `file_scan_logs`
--
ALTER TABLE `file_scan_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `scan_logs`
--
ALTER TABLE `scan_logs`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`);

-- --------------------------------------------------------

--
-- Table structure for table `complaints`
--

CREATE TABLE `complaints` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `name` varchar(100) NOT NULL,
  `email` varchar(150) NOT NULL,
  `category` varchar(80) NOT NULL,
  `message` text NOT NULL,
  `status` enum('New','In Progress','Resolved') NOT NULL DEFAULT 'New',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `file_scan_logs`
--
ALTER TABLE `file_scan_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=22;

--
-- AUTO_INCREMENT for table `scan_logs`
--
ALTER TABLE `scan_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT for table `complaints`
--
ALTER TABLE `complaints`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

ALTER TABLE `complaints`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
