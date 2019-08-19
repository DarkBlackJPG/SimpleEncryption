using System.Windows;
using System.Windows.Input;

namespace SimpleEncryption
{
    /// <summary>
    /// Interaction logic for ErrorWindow.xaml
    /// </summary>
    public partial class ErrorWindow : Window
    {
        public ErrorWindow(string Capction, string Text)
        {
            InitializeComponent();
            messageBox.AppendText(Text);
            TitleBox.Text += Capction;
            
        }
        private void CloseWindow(object sender, RoutedEventArgs e)
        {
            Close();
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
    }
}
