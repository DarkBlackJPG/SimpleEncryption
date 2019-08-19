using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.Data.SQLite;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Windows.Threading;

namespace SimpleEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    /// 


    
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            mediaPlayer.Stop();
            mediaPlayerAES.Stop();
            Caesar.IsChecked = true;
            ObservableCollection<string> DESList = new ObservableCollection<string>();
            DESList.Add("1. Start");
            DESList.Add("2. Initial Setup");
            DESList.Add("3. Key Generating");
            DESList.Add("4. PC-1");
            DESList.Add("5. Shift Tables");
            DESList.Add("6. PC-2");
            DESList.Add("7. Initial Permutation");
            DESList.Add("8. Feistel Network and the DES diagram");
            DESList.Add("9. The 'F' function");
            DESList.Add("10. E-bit selection");
            DESList.Add("11. How are the keys used?");
            DESList.Add("12. Substitution Boxes");
            DESList.Add("13. Permutation Boxes");
            DESList.Add("14. Inverse Permutation");
            DESList.Add("15. End");
            DESSelectorBox.ItemsSource = DESList;

            

            ObservableCollection<string> AESList = new ObservableCollection<string>();
            AESList.Add("1. Start");
            AESList.Add("2. Input");
            AESList.Add("3. Encryption process");
            AESList.Add("4. Types of transformations");
            AESList.Add("5. SubBytes");
            AESList.Add("6. ShiftRows");
            AESList.Add("7. MixColumns");
            AESList.Add("8. AddRoundKey");
            AESList.Add("9. Example");
            AESList.Add("10. KeySchedule");
            AESList.Add("11. End");
            AESSelectorBox.ItemsSource = AESList;




        }

        void LoadTextFromFile(string FilePath)
        {
            TextRange range;
            System.IO.FileStream fStream;
            if (System.IO.File.Exists(FilePath))
            {
                RichTextBox1.Foreground = Brushes.White;
                range = new TextRange(RichTextBox1.Document.ContentStart, RichTextBox1.Document.ContentEnd);
                fStream = new System.IO.FileStream(FilePath, System.IO.FileMode.OpenOrCreate);
                range.Load(fStream, System.Windows.DataFormats.Rtf);
                fStream.Close();

            }
            RichTextBox1.Foreground = Brushes.White;
        }
        private void CloseWindow(object sender, RoutedEventArgs e)
        {
            Close();
        }
        private void DESJump(object sender, RoutedEventArgs args)
        {
            
            int index = DESSelectorBox.SelectedIndex;
            try
            {
                if (index == -1)
                    throw new Exception("You have to select an item first!");
                double[] times = new double[15];
                times[0] = 0;
                times[1] = 7;
                times[2] = 12;
                times[3] = 16;
                times[4] = 28;
                times[5] = 59;
                times[6] = 77;
                times[7] = 101;
                times[8] = 109;
                times[9] = 115;
                times[10] = 124;
                times[11] = 141;
                times[12] = 160;
                times[13] = 177;
                times[14] = 190;
                mediaPlayer.Play();
                mediaPlayer.Position = TimeSpan.FromSeconds(times[index]);
                    
            } catch (Exception ex)
            {
                new ErrorWindow("Error with input!", ex.Message).ShowDialog();
            }
         

        }
        private void AESJump(object sender, RoutedEventArgs args)
        {
            int index = AESSelectorBox.SelectedIndex;
            try
            {
                if (index == -1)
                    throw new Exception("You have to select an item first!");
                double[] times = new double[15];
                times[0] = 3;
                times[1] = 14;
                times[2] = 33;
                times[3] = 57;
                times[4] = 61;
                times[5] = 82;
                times[6] = 98;
                times[7] = 119;
                times[8] = 144;
                times[9] = 172;
                times[10] = 261;
                mediaPlayerAES.Play();
                mediaPlayerAES.Position = TimeSpan.FromSeconds(times[index]);
                
            }
            catch (Exception ex)
            {
                new ErrorWindow("Error with input!", ex.Message).ShowDialog();
            } 
        }


        private void WindowMove(object sender, MouseButtonEventArgs e)
        {
            if (e.ChangedButton == MouseButton.Left)
                DragMove();
        }

        private void MinimizeWindow(object sender, RoutedEventArgs e)
        {
            WindowState = WindowState.Minimized;
        }

        private void PlayVideo(object sender, RoutedEventArgs e)
        {
            mediaPlayer.Play();
        }

        private void PauseVideo(object sender, RoutedEventArgs e)
        {
            mediaPlayer.Pause();
        }

        private void StopVideo(object sender, RoutedEventArgs e)
        {
            mediaPlayer.Stop();
        }
        private void PlayVideoAES(object sender, RoutedEventArgs e)
        {
            mediaPlayerAES.Play();
        }

        private void PauseVideoAES(object sender, RoutedEventArgs e)
        {
            mediaPlayerAES.Pause();
        }

        private void StopVideoAES(object sender, RoutedEventArgs e)
        {
            mediaPlayerAES.Stop();
        }
        System.IO.StreamReader srcStreamReader = null;
        private byte[] getData(string data)
        {
            if (!data.Contains("-")) throw new Exception("Ne moze da se desifruje");
            data = data.TrimEnd('\n', '\r');
            string[] stringArray = data.Split('-');
            byte[] returnData = new byte[stringArray.Length];
            for (int i = 0; i < stringArray.Length; i++)
            {
                byte temp = 0x00;
                int x = Convert.ToInt32("0x" + stringArray[i], 16);
                if (x > 255)
                {
                    throw new Exception("Nije dobar fajl, nemoguca dekripcija");
                }
                else
                {
                    byte[] g = new byte[] { Convert.ToByte(x) };
                    temp = g[0];
                }
                returnData[i] = temp;

            }
            return returnData;
        }
        private void DESEncrypt(string plaintext, string key, bool readFromFile = false, bool printToFile = false)
        {
            if (readFromFile && srcStreamReader != null)
            {
                plaintext = srcStreamReader.ReadToEnd();
            }
            if (plaintext.Length <= 0)
                throw new Exception("No text found");
            DESCryptor cryptor = new DESCryptor(plaintext, key);

            cryptor.DESEncrypt();

            if (printToFile)
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "Text Documents(*.txt)|*.txt"
                };
                if (saveFileDialog.ShowDialog() == true)
                    File.WriteAllText(saveFileDialog.FileName, BitConverter.ToString(cryptor.CipherText));
            } else
            {
                dstText.AppendText(BitConverter.ToString(cryptor.CipherText));
            }

        }
        private void DESDecrypt(string cipherText, string key, bool readFromFile = false, bool printToFile = false) {
            if (readFromFile && srcStreamReader != null)
            {
                cipherText = srcStreamReader.ReadToEnd();
            }
            if (cipherText.Length <= 0)
                throw new Exception("No text found");
            DESCryptor cryptor = new DESCryptor(getData(cipherText), key);

            cryptor.DESDecrypt();

            if (printToFile)
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "Text Documents(*.txt)|*.txt"
                };
                if (saveFileDialog.ShowDialog() == true)
                    File.WriteAllText(saveFileDialog.FileName, Encoding.Unicode.GetString(cryptor.InverseCipherText));
            }
            else
            {
                dstText.AppendText(Encoding.Unicode.GetString(cryptor.InverseCipherText));
            }
        }
        private void AESEncrypt(string plaintext, string key, bool readFromFile = false, bool printToFile = false)
        {
            if (readFromFile && srcStreamReader != null)
            {
                plaintext = srcStreamReader.ReadToEnd();
            }
            if (plaintext.Length <= 0)
                throw new Exception("No text found");
           
            AESCryptor cryptor = new AESCryptor(plaintext, key);

            cryptor.Encrypt();

            if (printToFile)
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "Text Documents(*.txt)|*.txt"
                };
                if (saveFileDialog.ShowDialog() == true)
                    File.WriteAllText(saveFileDialog.FileName, BitConverter.ToString(cryptor.EncryptedMessage));
            }
            else
            {
                dstText.AppendText(BitConverter.ToString(cryptor.EncryptedMessage));
            }
        }
        private void AESDecrypt(string cipherText, string key, bool readFromFile = false, bool printToFile = false) {
            if (readFromFile && srcStreamReader != null)
            {
                cipherText = srcStreamReader.ReadToEnd();
            }
            if (cipherText.Length <= 0)
                throw new Exception("No text found");
            AESCryptor cryptor = new AESCryptor(getData(cipherText), key);

            cryptor.Decrypt();

            if (printToFile)
            {
                SaveFileDialog saveFileDialog = new SaveFileDialog()
                {
                    Filter = "Text Documents(*.txt)|*.txt"
                };
                if (saveFileDialog.ShowDialog() == true)
                    File.WriteAllText(saveFileDialog.FileName , Encoding.Unicode.GetString(cryptor.PlainText));
            }
            else
            {
                dstText.AppendText(Encoding.Unicode.GetString(cryptor.PlainText));
            }

        }
        string StringFromRichTextBox(RichTextBox rtb)
        {
            TextRange textRange = new TextRange(
                rtb.Document.ContentStart,
                rtb.Document.ContentEnd
            );
            return textRange.Text;
        }
        int RichTextBoxLength(RichTextBox rtb)
        {
            TextRange textRange = new TextRange(
                rtb.Document.ContentStart,
                rtb.Document.ContentEnd
            );
            return textRange.Text.Length;
        }
        private void ExecuteButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (algorithmComboBox.SelectedIndex == -1 &&
                    directionComboBox.SelectedIndex == -1 &&
                    srcComboox.SelectedIndex == -1 &&
                    dstCombobox.SelectedIndex == -1)
                {
                    throw new Exception("All options are not chosen!");
                }

                if (PasswordBox.Password == "")
                    throw new Exception("Password not selected!");


                dstText.Document.Blocks.Clear();
                bool isDESAlgorithm = algorithmComboBox.SelectedIndex == 0;
                bool isEncryption = directionComboBox.SelectedIndex == 0;
                bool isSrcFile = srcComboox.SelectedIndex == 1;
                bool isDstFile = dstCombobox.SelectedIndex == 1;

                if (!isSrcFile && RichTextBoxLength(srcText) <= 0)
                    throw new Exception("Source text is not typed in!");


                if (isSrcFile)
                {
                    Microsoft.Win32.OpenFileDialog dialogBox = new Microsoft.Win32.OpenFileDialog
                    {
                        DefaultExt = ".txt",
                        Filter = "Text documents (.txt)|*.txt",
                    };
                    if (dialogBox.ShowDialog() == true)
                    {
                        string filename = dialogBox.FileName;
                        if (System.IO.File.Exists(filename))
                        {
                            srcStreamReader = new StreamReader(filename);

                        }
                        else
                        {
                            new ErrorWindow("Warning!", "Selected filepath doesn't exist. Please try again.").ShowDialog();
                            srcStreamReader = null;
                        }

                    }
                    else
                    {
                        new ErrorWindow("ERROR!", "Source file was not chosen, please choose a file destination").ShowDialog();
                        dialogBox = null;
                        srcStreamReader = null;

                    }
                }
                if (isDESAlgorithm)
                {
                    if (isEncryption)
                    {
                        if (isSrcFile)
                            DESEncrypt("", PasswordBox.Password, true, isDstFile);
                        else
                            DESEncrypt(StringFromRichTextBox(srcText), PasswordBox.Password, false, isDstFile);
                    }
                    else
                    {
                        if (isSrcFile)
                            DESDecrypt("", PasswordBox.Password, true, isDstFile);
                        else
                            DESDecrypt(StringFromRichTextBox(srcText), PasswordBox.Password, false, isDstFile);
                    }
                }
                else
                {
                    if (isEncryption)
                    {
                        if (isSrcFile)
                            AESEncrypt("", PasswordBox.Password, true, isDstFile);
                        else
                            AESEncrypt(StringFromRichTextBox(srcText), PasswordBox.Password, false, isDstFile);
                    }
                    else
                    {
                        if (isSrcFile)
                            AESDecrypt("", PasswordBox.Password, true, isDstFile);
                        else
                            AESDecrypt(StringFromRichTextBox(srcText), PasswordBox.Password, false, isDstFile);
                    }
                }
            }
            catch(Exception ex)
            {
                new ErrorWindow("Error while executing!", ex.Message).ShowDialog();
            }

            
        }

        private void SrcComboox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
         
            
        }
        private void DstCombobox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        { 
        }
        SQLiteConnection sQLiteConnection;
        private static Random rng = new Random();
        struct Question { public int id; public string Text; }
        struct QuestionData {
            string questionText;
            int questionId;
            List<CheckBox> answerCheckBoxes;

            public int QuestionId{
                get; set;
            }
            public string QuestionText
            {
                get; set;
            }
            public List<CheckBox> AnswerCheckBoxes
            {
                get; set;
            }


        }
        HashSet<int> list; // Id svih pitanja
        List<QuestionData> currentTestQuestionData;
        List<StackPanel> questionStackPanelList;
        Button confirmationButton;
        private void GenerateTestButton_Click(object sender, RoutedEventArgs e)
        {
          
            try
            {
                questionStackPanelList = new List<StackPanel>();
                QuestionContainer.HorizontalAlignment = HorizontalAlignment.Center;
                QuestionContainer.Visibility = Visibility.Visible;
                GenerateTestButton.Visibility = Visibility.Hidden;

                list = new HashSet<int>();

                while (list.Count != 10)
                {
                    int temp = rng.Next(1, 17);
                    list.Add(temp);
                }

                sQLiteConnection = new SQLiteConnection(@"Data Source=..\TestDB.db;Version=3;");
                sQLiteConnection.Open();
                try
                {
                    SQLiteCommand sQLiteCommand = new SQLiteCommand(sQLiteConnection);
                    int[] ids = list.ToArray();
                    string idString = ids[0].ToString();
                    for (int i = 1; i < ids.Length; i++)
                    {
                        idString += ", " + ids[i].ToString();
                    }
                    sQLiteCommand.CommandText = "SELECT Questions.id, Questions.Text " +
                        "FROM Questions where Questions.id IN (" + idString + ")  " +
                        "Group by Questions.id";
                    SQLiteDataReader dataReader = sQLiteCommand.ExecuteReader();
                    List<Question> questionList = new List<Question>();
                    while (dataReader.Read())
                    {
                        Question x = new Question
                        {
                            id = Convert.ToInt32(dataReader.GetValue(0)),
                            Text = dataReader.GetValue(1).ToString()
                        };
                        questionList.Add(x);
                    }
                    questionList.Shuffle();
                    dataReader.Close();
                    currentTestQuestionData = new List<QuestionData>();
                    foreach (Question question in questionList)
                    {

                        StackPanel questionStackPanel = new StackPanel
                        {
                            Name = "QuestionPanel_" + question.id,
                            HorizontalAlignment = HorizontalAlignment.Center
                        };
                        QuestionData temp = new QuestionData()
                        {
                            QuestionText = question.Text,
                            QuestionId = question.id,
                            AnswerCheckBoxes = new List<CheckBox>()
                        };
                        Thickness thick = new Thickness(0, 20, 0, 20);
                        questionStackPanel.Margin = thick;
                        Border stackPanelBorder = new Border()
                        {
                            Background = Brushes.DarkGray,
                            BorderBrush = Brushes.DarkGray,
                            BorderThickness = new Thickness(1)
                        };
                        questionStackPanel.Children.Add(stackPanelBorder);

                        TextBlock questionText = new TextBlock()
                        {
                            Text = question.Text,
                            HorizontalAlignment = HorizontalAlignment.Center,
                            FontSize = 20
                        };
                        questionStackPanel.Children.Add(questionText);
                        Grid grid = new Grid
                        {

                            HorizontalAlignment = HorizontalAlignment.Center,

                            VerticalAlignment = VerticalAlignment.Top,

                        };

                        ColumnDefinition gridCol1 = new ColumnDefinition();
                        ColumnDefinition gridCol2 = new ColumnDefinition();
                        grid.ColumnDefinitions.Add(gridCol1);
                        grid.ColumnDefinitions.Add(gridCol2);

                        SQLiteCommand command = new SQLiteCommand(sQLiteConnection)
                        {
                            CommandText = "Select Answers.Text, Answers.id from Answers where Answers.questionId = " + question.id.ToString()
                        };

                        SQLiteDataReader questions = command.ExecuteReader();
                        int rowIncrement = 0;
                        for (int i = 0; questions.Read(); i++)
                        {
                            string checkBoxContent = questions.GetString(0).ToString();
                            string checkBoxName = questions.GetValue(1).ToString();
                            CheckBox checkBox = new CheckBox()
                            {
                                Name = "Answer_" + checkBoxName,
                                FontSize = 15,
                                MaxWidth = 400
                                
                            };
                            temp.AnswerCheckBoxes.Add(checkBox);
                            TextBlock tb = new TextBlock()
                            {
                                Text = checkBoxContent,
                                TextWrapping = TextWrapping.Wrap
                            };

                            checkBox.Content = tb;
                            grid.Children.Add(checkBox);
                            checkBox.SetValue(Grid.RowProperty, rowIncrement);
                            if (i % 2 == 0)
                            {
                                checkBox.SetValue(Grid.ColumnProperty, 0);
                                RowDefinition row = new RowDefinition();
                                grid.RowDefinitions.Add(row);
                            }
                            else
                            {
                                checkBox.SetValue(Grid.ColumnProperty, 1);
                                RowDefinition row = new RowDefinition();
                                grid.RowDefinitions.Add(row);
                                rowIncrement++;
                            }
                           

                        }
                        currentTestQuestionData.Add(temp);
                        questionStackPanel.Children.Add(grid);
                        questionStackPanelList.Add(questionStackPanel);
                        QuestionContainer.Children.Add(questionStackPanel);
                    }
                }
                catch (Exception ex)
                {
                    new ErrorWindow("Fatal Error", ex.Message).ShowDialog();
                }
            }
            catch (Exception ex)
            {
                new ErrorWindow("Fatal Error", ex.Message).ShowDialog();
            }
            finally
            {
                sQLiteConnection.Close();
                confirmationButton = new Button()
                {
                    Content = "Finish Test",
                    FontSize = 50,
                    Background = Brushes.Transparent,
                    Margin = new Thickness(30)
                };
                confirmationButton.Click += new RoutedEventHandler(ConfirmAnswers);
                QuestionContainer.Children.Add(confirmationButton);
            }


        }
        
        struct IncorrectAnswerData
        {
            string questionText;
            List<string> answerText;

            public string QuestionText
            {
                get;set;
            }
            public List<string> AnswerText
            {
                get; set;
            }
        }
        void ConfirmAnswers(object sender, RoutedEventArgs arg)
        {
            try
            { 
                sQLiteConnection = new SQLiteConnection(@"Data Source=..\TestDB.db;Version=3;");
                if (list == null || currentTestQuestionData == null)
                {
                    throw new Exception("Question List or Question Data are not initialized!\nFatal Error!");
                }

                List<IncorrectAnswerData> incorrectAnswerDatas = new List<IncorrectAnswerData>();
                foreach( QuestionData qData in currentTestQuestionData )
                {
                    List<int> checkedAnswers = new List<int>();
                    List<int> correctAnswers = new List<int>();
                    foreach(CheckBox check in qData.AnswerCheckBoxes)
                    {
                        if ((bool)check.IsChecked)
                            checkedAnswers.Add(
                                    Convert.ToInt32(check.Name.Split('_')[1].ToString())
                                );
                    }
                    sQLiteConnection.Open();
                    SQLiteCommand sCommand = new SQLiteCommand(sQLiteConnection)
                    {
                        CommandText = "select CorrectAnswers.answerId AS Odgovor from CorrectAnswers where CorrectAnswers.questonId = " + qData.QuestionId.ToString()
                    };
                    SQLiteDataReader sQ = sCommand.ExecuteReader();
                    while (sQ.Read())
                        correctAnswers.Add(sQ.GetInt32(0));

                    var answerCheck = checkedAnswers.Except(correctAnswers).ToList();
                    int emptyCheck = correctAnswers.Except(checkedAnswers).ToList().Count;
                    if (answerCheck.Count > 0) {
                        IncorrectAnswerData incorrect = new IncorrectAnswerData() {
                            QuestionText = qData.QuestionText,
                            AnswerText = new List<string>()
                        };
                        int i = 0;
                        foreach(var answer in answerCheck)
                        {
                            while(answer != Convert.ToInt32(qData.AnswerCheckBoxes[i].Name.Split('_')[1].ToString()))
                            {
                                i++;
                            }
                            incorrect.AnswerText.Add(((TextBlock)qData.AnswerCheckBoxes[i].Content).Text);
                        }
                        incorrectAnswerDatas.Add(incorrect);


                    } else if (answerCheck.Count == 0 && emptyCheck > 0)
                    {
                        IncorrectAnswerData incorrect = new IncorrectAnswerData()
                        {
                            QuestionText = qData.QuestionText,
                            AnswerText = new List<string>()
                };
                        incorrect.AnswerText.Add("Question left empty");
                        incorrectAnswerDatas.Add(incorrect);
                    }
                    sQLiteConnection.Close();
                }
                if (incorrectAnswerDatas.Count > 0)
                {
                    string builder = "";
                    foreach (var incorrectAnswer in incorrectAnswerDatas)
                    {
                        builder += incorrectAnswer.QuestionText;
                        builder += "\n";
                        foreach (var error in incorrectAnswer.AnswerText)
                        {
                            builder += "- " + error + "\n";
                        }
                        builder += "------------------------------------\n";
                    }
                    builder += "\n " + (10 - incorrectAnswerDatas.Count) + "/10 correct answers \n";
                    new ErrorWindow("Incorrect Answers!", builder).ShowDialog();
                } else if (incorrectAnswerDatas.Count == 0)
                {
                    new ErrorWindow("Congratulations!", "Everything is correct!").ShowDialog();
                }
            } 
            catch (Exception ex)
            {
                new ErrorWindow("Fatal error", ex.Message).ShowDialog();
            }
            finally
            {
                QuestionContainer.Visibility = Visibility.Hidden;
                GenerateTestButton.Visibility = Visibility.Visible;
                list = null;
                currentTestQuestionData = null;
                foreach(var panel in questionStackPanelList)
                {
                    QuestionContainer.Children.Remove(panel);
                }
                QuestionContainer.Children.Remove(confirmationButton);
            }
        }

        private void Caesar_Checked(object sender, RoutedEventArgs e)
        {
            LoadTextFromFile(@"..\istorija.rtf");
        }

        private void Crypto_Checked(object sender, RoutedEventArgs e)
        {
            LoadTextFromFile(@"..\kriptografija.rtf");
        }

        private void DES_Checked(object sender, RoutedEventArgs e)
        {
            LoadTextFromFile(@"..\des.rtf");
        }

        private void AES_Checked(object sender, RoutedEventArgs e)
        {
            LoadTextFromFile(@"..\aes.rtf");
        }

        private void Hash_Checked(object sender, RoutedEventArgs e)
        {
            LoadTextFromFile(@"..\hash.rtf");
        }

       
    }

    public static class IListExtensions
    {
        private static Random rng = new Random();

        public static void Shuffle<T>(this IList<T> list)
        {

            int n = list.Count;
            while (n > 1)
            {
                n--;
                int k = rng.Next(n + 1);
                T value = list[k];
                list[k] = list[n];
                list[n] = value;
            }

        }
    }
}
