int WINAPI WinMain(...)
{
   const char szUniqueNamedMutex[] = "com_mycompany_apps_appname";
   HANDLE hHandle = CreateMutex( NULL, TRUE, szUniqueNamedMutex );
   if( ERROR_ALREADY_EXISTS == GetLastError() )
   {
      // Program already running somewhere
      return(1); // Exit program
   }

   // Program runs...

   // Upon app closing:
   ReleaseMutex( hHandle ); // Explicitly release mutex
   CloseHandle( hHandle ); // close handle before terminating
   return( 1 );
}