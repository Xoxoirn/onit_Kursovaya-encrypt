using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Kursovaya_ONIT_1
{
    /// <summary>
    /// Логика взаимодействия для MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        List<Encryption> EncryptionList = new List<Encryption>();
        public MainWindow()
        {
            InitializeComponent();
            aesCheck.Checked += AesCheck_Checked; desCheck.Checked += DesCheck_Checked;
        }

        private void DesCheck_Checked(object sender, RoutedEventArgs e)
        {
            aesCheck.IsChecked = false;
        }

        private void AesCheck_Checked(object sender, RoutedEventArgs e)
        {
            desCheck.IsChecked = false;
        }

        private void FileDrop(object sender, DragEventArgs e)
        {
            var paths = (string[])e.Data.GetData("FileDrop");
            long sumByte = 0;
            try
            {
                foreach (var item in paths)
                {
                    EncryptionList.Add(new Encryption(item, "0"));
                    using (var stream = File.OpenRead(item))
                    {
                        sumByte += stream.Length;
                        WriteLog("Файл " + item + $" загружен ({stream.Length} byte)");
                    }
                }
                WriteLog("Всего файлов: " + paths.Length + $"({sumByte} byte)");
                UpdQuery();
            }
            catch (Exception ex)
            {
                WriteLog(ex.Message, Brushes.Red);
            }
        }

        private void OpenClick(object sender, RoutedEventArgs e)
        {
            OpenFileDialog fileManager = new OpenFileDialog();
            fileManager.ShowDialog();
            var item = fileManager.FileName;
            if (item != "")
            {
                EncryptionList.Add(new Encryption(item, "0"));
                using (var stream = File.OpenRead(item))
                {
                    WriteLog("Файл " + item + $" загружен ({stream.Length} byte)");
                }
                UpdQuery();
            }
        }

        private void WriteLog(string message, System.Windows.Media.SolidColorBrush color = null)
        {
            if (color == null)
                color = System.Windows.Media.Brushes.Black;
            var text = new TextBlock() { Text = message, Foreground = color };
            Log.Items.Add(text);
            Log.ScrollIntoView(text);
            Log.SelectedItem = text;
        }

        private void UpdQuery()
        {
            int i = 0;
            Query.Items.Clear();
            foreach (var enc in EncryptionList)
            {
                TextBlock text;
                if (i == 0)
                {
                    text = new TextBlock() { Text = enc.SourceFilePath, Foreground = System.Windows.Media.Brushes.DarkGreen };
                }
                else
                {
                    text = new TextBlock() { Text = enc.SourceFilePath, Foreground = System.Windows.Media.Brushes.Black };
                }
                Query.Items.Add(text);
                i++;
            }
        }

        private void EncryptClick(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyRepeat())
            {
                MessageBox.Show("Пароли не совпадают", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            try
            {
                var encFile = EncryptionList.FirstOrDefault();
                SaveFileDialog fileManager = new SaveFileDialog();
                fileManager.Filter = "Файлы enc|*.enc";
                fileManager.FileName = encFile.GetNameFileWithoutFormat() + '.' + encFile.FormatFile + ".enc";
                fileManager.FileOk += FileManager_EncryptGo;
                fileManager.ShowDialog();
            }
            catch (Exception ex)
            {
                WriteLog(ex.Message, Brushes.DarkRed);
            }
        }

        private void DecryptClick(object sender, RoutedEventArgs e)
        {
            if (!CheckKeyRepeat())
            {
                MessageBox.Show("Пароли не совпадают", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            try
            {
                var encFile = EncryptionList.FirstOrDefault();
                SaveFileDialog fileManager = new SaveFileDialog();
                fileManager.FileName = encFile.GetNameFileWithoutFormat();
                fileManager.FileOk += FileManager_DecryptGo;
                fileManager.ShowDialog();
            }
            catch (Exception ex)
            {
                WriteLog(ex.Message, Brushes.DarkRed);
            }
        }

        private async void FileManager_DecryptGo(object sender, System.ComponentModel.CancelEventArgs e)
        {

            var encFile = EncryptionList.FirstOrDefault();
            var item = ((SaveFileDialog)sender).FileName;
            try
            {
                if (item != "")
                {
                    encFile.Key = Key.Password;
                    encFile.UseDES = desCheck.IsChecked.Value;

                    await encFile.DecryptInFileAsync(item);
                    EncryptionList.Remove(encFile);
                }
                WriteLog("Файл " + item + " успешно сохранен", Brushes.DarkBlue);
                UpdQuery();
            }
            catch (Exception ex)
            {
                WriteLog(ex.Message, Brushes.DarkRed);
            }
        }

        private async void FileManager_EncryptGo(object sender, System.ComponentModel.CancelEventArgs e)
        {
            var encFile = EncryptionList.FirstOrDefault();
            var item = ((SaveFileDialog)sender).FileName;
            try
            {
                if (item != "")
                {
                    encFile.Key = Key.Password;
                    encFile.UseDES = desCheck.IsChecked.Value;

                    await encFile.EncryptInFileAsync(item);
                    EncryptionList.Remove(encFile);
                }
                WriteLog("Файл " + item + " успешно сохранен", Brushes.DarkBlue);
                UpdQuery();
            }
            catch (Exception ex)
            {
                WriteLog(ex.Message, Brushes.DarkRed);
            }
        }

        private bool CheckKeyRepeat()
        {
            if (Key.Password == RKey.Password)
                return true;
            return false;
        }

        private void ClearQuery(object sender, RoutedEventArgs e)
        {
            EncryptionList.Clear();
            EncryptionList = new List<Encryption>();
            UpdQuery();
        }
    }
}
