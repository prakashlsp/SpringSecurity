package com.Asti.jobhunt.exception;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
public class AccessDeniedException extends RuntimeException
{
	 String msg;
}
