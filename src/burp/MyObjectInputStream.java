/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package burp;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;

/**
 *
 * @author omercohen
 */
public class MyObjectInputStream extends ObjectInputStream 
{
    
    public MyObjectInputStream(InputStream in) throws IOException
    {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException
    {
        return Class.forName(desc.getName(), false, BurpExtender.classLoader);
    }
}