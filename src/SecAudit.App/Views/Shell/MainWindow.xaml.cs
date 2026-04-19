using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using SecAudit.App.ViewModels;
using Wpf.Ui;
using Wpf.Ui.Controls;

namespace SecAudit.App.Views.Shell;

[SupportedOSPlatform("windows")]
public partial class MainWindow : FluentWindow
{
    public MainWindow(ShellViewModel viewModel, IServiceProvider services)
    {
        InitializeComponent();
        DataContext = viewModel;

        // Let the NavigationView resolve pages via DI.
        RootNavigation.SetPageService(new PageService(services));
        Loaded += (_, _) => RootNavigation.Navigate(typeof(Pages.DashboardPage));
    }
}

[SupportedOSPlatform("windows")]
internal sealed class PageService : IPageService
{
    private readonly IServiceProvider _services;

    public PageService(IServiceProvider services) => _services = services;

    public T? GetPage<T>() where T : class
    {
        if (!typeof(System.Windows.FrameworkElement).IsAssignableFrom(typeof(T)))
        {
            throw new InvalidOperationException("Page must be FrameworkElement.");
        }
        return _services.GetService<T>();
    }

    public System.Windows.FrameworkElement? GetPage(Type pageType)
    {
        ArgumentNullException.ThrowIfNull(pageType);
        return _services.GetService(pageType) as System.Windows.FrameworkElement;
    }
}
