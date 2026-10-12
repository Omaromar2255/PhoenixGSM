file_path = r'c:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit\MonitoringStudio\MainWindow.xaml'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

content = content.replace(' Style="{StaticResource FilterCardBtn}"', '')

with open(file_path, 'w', encoding='utf-8') as f:
    f.write(content)
print('Fixed XAML styles.')
