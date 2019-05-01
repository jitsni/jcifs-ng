/* jcifs msrpc client library in Java
 * Copyright (C) 2006  "Michael B. Allen" <jcifs at samba dot org>
 *                     "Eric Glass" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.dcerpc;


/**
 * Unicode string type wrapper
 * 
 */
public class UnicodeString extends rpc.unicode_string {

    boolean zterm;


    /**
     * 
     * @param zterm
     *            whether the string should be zero terminated
     */
    public UnicodeString ( boolean zterm ) {
        this.zterm = zterm;
    }


    /**
     * 
     * @param rus
     *            wrapped string
     * @param zterm
     *            whether the string should be zero terminated
     */
    public UnicodeString ( rpc.unicode_string rus, boolean zterm ) {
        this.length = rus == null ? 0 : rus.length;
        this.maximum_length = rus == null ? 0 : rus.maximum_length;
        this.buffer = rus == null ? null : rus.buffer;
        this.zterm = zterm;
    }


    /**
     * 
     * @param str
     *            wrapped string
     * @param zterm
     *            whether the string should be zero terminated
     */
    public UnicodeString ( String str, boolean zterm ) {
        this.zterm = zterm;

        int len = str == null ? 0 : str.length();
        int zt = zterm ? 1 : 0;

        this.length = this.maximum_length = (short) ( ( len + zt ) * 2 );
        if (str != null) {
            buffer = new short[len + zt];
        } else {
            buffer = null;
        }

        int i;
        for ( i = 0; i < len; i++ ) {
            this.buffer[ i ] = (short) str.charAt(i);
        }
        if ( zterm ) {
            this.buffer[ i ] = (short) 0;
        }
    }


    @Override
    public String toString () {
        int len = this.length / 2 - ( this.zterm ? 1 : 0 );
        char[] ca = new char[len];
        for ( int i = 0; i < len; i++ ) {
            ca[ i ] = (char) this.buffer[ i ];
        }
        return new String(ca, 0, len);
    }
}
