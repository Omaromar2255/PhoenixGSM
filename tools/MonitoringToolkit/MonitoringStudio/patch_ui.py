import re

file_path = r'c:\Users\pc5\softwer\PhoenixGSM\tools\MonitoringToolkit\MonitoringStudio\MainWindow.xaml'
with open(file_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Define the new unified UI
new_ui = '''        <!-- ╔══════════════════════════════════════════════════════════╗ -->
        <!-- ║ ROW 2 & 3: UNIFIED MONITORING CARDS & FILTERS            ║ -->
        <!-- ╚══════════════════════════════════════════════════════════╝ -->
        <Border Grid.Row="2" Grid.RowSpan="2" Background="{StaticResource CardBgBrush}" 
                BorderBrush="{StaticResource BorderDarkBrush}" BorderThickness="1" 
                CornerRadius="8" Padding="12,12" Margin="0,0,0,10">
            <Grid>
                <Grid.RowDefinitions>
                    <!-- Header & Master Controls -->
                    <RowDefinition Height="Auto" />
                    <!-- Unified Cards (WrapPanel) -->
                    <RowDefinition Height="Auto" />
                    <!-- Exclusions -->
                    <RowDefinition Height="Auto" />
                </Grid.RowDefinitions>

                <!-- HEADER & MASTER CONTROLS -->
                <Grid Grid.Row="0" Margin="0,0,0,12">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="*" />
                        <ColumnDefinition Width="Auto" />
                        <ColumnDefinition Width="250" />
                        <ColumnDefinition Width="Auto" />
                    </Grid.ColumnDefinitions>
                    
                    <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                        <TextBlock Text="🎯" FontSize="18" VerticalAlignment="Center" Margin="0,0,8,0" />
                        <StackPanel VerticalAlignment="Center">
                            <TextBlock Text="Unified Sensors &amp; Categories" FontSize="12" FontWeight="Bold" Foreground="#00E5FF" />
                            <TextBlock Text="Toggle capture (ON/OFF) and filter view by category" FontSize="10" Foreground="{StaticResource TextMutedBrush}" />
                        </StackPanel>
                    </StackPanel>

                    <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,15,0">
                        <Button Content="✅ Enable All" Command="{Binding EnableAllSensorsCommand}" Style="{StaticResource ModernBtn}" Padding="10,4" FontSize="11" Margin="0,0,6,0" />
                        <Button Content="⏹️ Disable All" Command="{Binding DisableAllSensorsCommand}" Style="{StaticResource ModernBtn}" Padding="10,4" FontSize="11" />
                    </StackPanel>

                    <!-- Search Box -->
                    <Grid Grid.Column="3" Margin="0,0,10,0">
                        <TextBox Text="{Binding SearchText, UpdateSourceTrigger=PropertyChanged}" 
                                 Background="#0C0F17" Foreground="#FFFFFF" BorderBrush="#2A3347" 
                                 CaretBrush="#00E5FF" Padding="8,5" FontSize="12" VerticalContentAlignment="Center">
                            <TextBox.Resources>
                                <Style TargetType="{x:Type Border}">
                                    <Setter Property="CornerRadius" Value="6"/>
                                </Style>
                            </TextBox.Resources>
                        </TextBox>
                        <TextBlock Text="🔍 Filter events..." Foreground="{StaticResource TextMutedBrush}" FontSize="11" Margin="10,0,0,0" VerticalAlignment="Center" IsHitTestVisible="False">
                            <TextBlock.Style>
                                <Style TargetType="TextBlock">
                                    <Setter Property="Visibility" Value="Collapsed" />
                                    <Style.Triggers>
                                        <DataTrigger Binding="{Binding SearchText}" Value="">
                                            <Setter Property="Visibility" Value="Visible" />
                                        </DataTrigger>
                                    </Style.Triggers>
                                </Style>
                            </TextBlock.Style>
                        </TextBlock>
                    </Grid>

                    <CheckBox Grid.Column="4" IsChecked="{Binding AutoScroll}" Foreground="{StaticResource TextPrimaryBrush}" VerticalAlignment="Center">
                        <TextBlock Text="Auto-Scroll" FontSize="11" Foreground="{StaticResource TextMutedBrush}" />
                    </CheckBox>
                </Grid>

                <!-- UNIFIED CARDS (WRAP PANEL) -->
                <WrapPanel Grid.Row="1" Orientation="Horizontal" Margin="-4,0,-4,12">
                    <WrapPanel.Resources>
                        <Style x:Key="FilterCardBtn" TargetType="Button">
                            <Setter Property="Background" Value="#1A202F" />
                            <Setter Property="Foreground" Value="#FFFFFF" />
                            <Setter Property="BorderBrush" Value="#2A3347" />
                            <Setter Property="BorderThickness" Value="1" />
                            <Setter Property="Cursor" Value="Hand" />
                            <Setter Property="Template">
                                <Setter.Value>
                                    <ControlTemplate TargetType="Button">
                                        <Border Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="8" Padding="10,8">
                                            <ContentPresenter />
                                        </Border>
                                    </ControlTemplate>
                                </Setter.Value>
                            </Setter>
                            <Style.Triggers>
                                <Trigger Property="IsMouseOver" Value="True">
                                    <Setter Property="Background" Value="#252D3E" />
                                </Trigger>
                            </Style.Triggers>
                        </Style>
                    </WrapPanel.Resources>

                    <!-- ALL CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="All" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsAllSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#00E5FF" />
                                        <Setter Property="Background" Value="#002B40" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🌐 All Events" Foreground="#FFFFFF" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding TotalEventsCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <TextBlock Grid.Row="1" Text="Global View" FontSize="10" Foreground="{StaticResource TextMutedBrush}" HorizontalAlignment="Center" />
                        </Grid>
                    </Button>

                    <!-- USB DRIVER CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="UsbDriver" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsUsbDriverSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#00E5FF" />
                                        <Setter Property="Background" Value="#002B40" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🔌 USB Driver" Foreground="#00E5FF" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding UsbCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsUsbMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding UsbMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- ADB PROXY CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="AdbProxy" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsAdbProxySelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#00FF9D" />
                                        <Setter Property="Background" Value="#003320" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🤖 ADB Proxy" Foreground="#00FF9D" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding AdbCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsAdbMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding AdbMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- COM PORT CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="SerialPort" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsSerialPortSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#FFC800" />
                                        <Setter Property="Background" Value="#332800" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="📟 COM / AT" Foreground="#FFC800" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding SerialCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsSerialMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding SerialMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- TOOLS PROCESS CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="Process" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsProcessSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#C084FC" />
                                        <Setter Property="Background" Value="#28103F" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="⚙️ Tools (Proc)" Foreground="#C084FC" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding ProcessCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsProcessMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding ProcessMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- CMD CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="Cmd" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsCmdSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#FFFFFF" />
                                        <Setter Property="Background" Value="#2A2A2A" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🖥️ CMD" Foreground="#FFFFFF" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding CmdCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsCmdMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding CmdMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- SHELL CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="Shell" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsShellSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#A5D6A7" />
                                        <Setter Property="Background" Value="#1B3320" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🐚 Shell" Foreground="#A5D6A7" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding ShellCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsShellMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding ShellMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- WEB URL CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="NetworkUrl" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsNetworkUrlSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#F43F5E" />
                                        <Setter Property="Background" Value="#40121A" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🌐 Web/URLs" Foreground="#F43F5E" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding NetworkCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsUrlMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding UrlMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- MTK CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="MediaTek" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsMediaTekSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#FF6D00" />
                                        <Setter Property="Background" Value="#331A00" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="⚡ MTK" Foreground="#FF6D00" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding MtkCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <TextBlock Grid.Row="1" Text="Auto-Capture" FontSize="10" Foreground="{StaticResource TextMutedBrush}" HorizontalAlignment="Center" Margin="0,3,0,3" />
                        </Grid>
                    </Button>

                    <!-- SPD CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="UnisocSpd" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsUnisocSpdSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#E040FB" />
                                        <Setter Property="Background" Value="#2E1033" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="💎 SPD" Foreground="#E040FB" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding SpdCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <TextBlock Grid.Row="1" Text="Auto-Capture" FontSize="10" Foreground="{StaticResource TextMutedBrush}" HorizontalAlignment="Center" Margin="0,3,0,3" />
                        </Grid>
                    </Button>

                    <!-- EDL CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="QualcommEdl" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsQualcommEdlSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#FF1744" />
                                        <Setter Property="Background" Value="#330810" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🔥 EDL 9008" Foreground="#FF1744" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding EdlCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <TextBlock Grid.Row="1" Text="Auto-Capture" FontSize="10" Foreground="{StaticResource TextMutedBrush}" HorizontalAlignment="Center" Margin="0,3,0,3" />
                        </Grid>
                    </Button>

                    <!-- APPLE CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="AppleIos" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsAppleIosSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#38BDF8" />
                                        <Setter Property="Background" Value="#0B283A" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="🍎 Apple iOS" Foreground="#38BDF8" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding AppleCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsAppleMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding AppleMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- TEMP AT CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="TempFileAt" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsTempFileAtSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#FB923C" />
                                        <Setter Property="Background" Value="#3D200E" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="📁 Temp AT" Foreground="#FB923C" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding TempAtCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsTempAtMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding TempAtMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- MTP CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="Mtp" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsMtpSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#2DD4BF" />
                                        <Setter Property="Background" Value="#0A332E" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="📁 MTP" Foreground="#2DD4BF" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding MtpCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsMtpMonitoringEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding MtpMonitoringStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>

                    <!-- VAULT FILES CARD -->
                    <Button Command="{Binding SelectCategoryCommand}" CommandParameter="ArtifactVault" Style="{StaticResource FilterCardBtn}" Margin="4" Width="135">
                        <Button.Style>
                            <Style TargetType="Button" BasedOn="{StaticResource FilterCardBtn}">
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding IsArtifactVaultSelected}" Value="True">
                                        <Setter Property="BorderBrush" Value="#FBBF24" />
                                        <Setter Property="Background" Value="#3A2F08" />
                                        <Setter Property="BorderThickness" Value="2" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Button.Style>
                        <Grid>
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*" />
                                <RowDefinition Height="Auto" />
                            </Grid.RowDefinitions>
                            <StackPanel Grid.Row="0" Margin="0,0,0,8">
                                <TextBlock Text="📦 Vault Files" Foreground="#FBBF24" FontWeight="SemiBold" FontSize="11" />
                                <TextBlock Text="{Binding ArtifactVaultCount}" Foreground="#FFFFFF" FontWeight="Bold" FontSize="16" Margin="0,4,0,0" />
                            </StackPanel>
                            <ToggleButton Grid.Row="1" IsChecked="{Binding IsArtifactVaultEnabled}" Style="{StaticResource SensorToggleBtn}" Height="22">
                                <TextBlock Text="{Binding ArtifactVaultStatusText}" FontSize="10" />
                            </ToggleButton>
                        </Grid>
                    </Button>
                </WrapPanel>

                <!-- ── EXCLUSIONS (ENGLISH) ── -->
                <Border Grid.Row="2" Background="#10141F" BorderBrush="#1F2636" BorderThickness="0,1,0,0" Padding="4,6,4,0">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto" />
                            <ColumnDefinition Width="*" />
                            <ColumnDefinition Width="Auto" />
                        </Grid.ColumnDefinitions>

                        <!-- Exclude Label -->
                        <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,12,0">
                            <TextBlock Text="🛡️ Exclude from View/Export:" FontSize="11" FontWeight="SemiBold" Foreground="#FF758F" VerticalAlignment="Center" />
                        </StackPanel>

                        <!-- Exclusion Checkboxes (Pill Chips) -->
                        <ScrollViewer Grid.Column="1" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Disabled">
                            <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                                <CheckBox IsChecked="{Binding HideUrls}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide URLs" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideAdb}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide ADB" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideUsb}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide USB" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideSerial}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide COM" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideProcesses}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide Tools" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideCmd}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide CMD" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideShell}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide Shell" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideTempAt}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide AT Files" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideApple}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide Apple" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideMtp}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide MTP" />
                                </CheckBox>

                                <CheckBox IsChecked="{Binding HideArtifacts}" Style="{StaticResource ExclusionCheckBox}">
                                    <TextBlock Text="🚫 Hide Vault" />
                                </CheckBox>
                            </StackPanel>
                        </ScrollViewer>

                        <!-- Right Exclusions Status Badge & Reset Button -->
                        <StackPanel Grid.Column="2" Orientation="Horizontal" VerticalAlignment="Center">
                            <Border Background="#25121A" BorderBrush="#F43F5E" BorderThickness="1" CornerRadius="4" Padding="7,2" Margin="0,0,6,0">
                                <TextBlock Text="{Binding ExclusionBadgeText}" FontSize="10.5" FontWeight="Bold" Foreground="#FFA4B4" VerticalAlignment="Center" />
                            </Border>

                            <Button Content="Reset Exclusions" Command="{Binding ResetExclusionsCommand}" 
                                    Style="{StaticResource RedActionBtn}" Height="23" Padding="8,1" FontSize="10.5"
                                    IsEnabled="{Binding HasActiveExclusions}" />
                        </StackPanel>
                    </Grid>
                </Border>
            </Grid>
        </Border>'''

# Find block to replace
start_idx = content.find('<!-- ╔══════════════════════════════════════════════════════════╗ -->\n        <!-- ║ ROW 2:')
end_idx = content.find('<!-- ╔══════════════════════════════════════════════════════════╗ -->\n        <!-- ║ ROW 4:')

if start_idx != -1 and end_idx != -1:
    content = content[:start_idx] + new_ui + '\n\n        ' + content[end_idx:]
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('Successfully updated UI.')
else:
    print('Could not find markers.')
